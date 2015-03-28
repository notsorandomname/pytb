
import os
import argparse
import linecache
import struct
import contextlib, subprocess
from pprint import pprint
from collections import namedtuple, OrderedDict
import logging
from logging import warning, debug

MemMap = namedtuple("MemMap", "start end perms offset dev inode filename")

PAGE_SIZE = 4096
INTERP_HEAD_OFFSET = 0x90b0
GENERATIONS_OFFSET = 0x35b00


class MemReader(object):

    def __init__(self, pid):
        self._pid = pid
        self._fh = None

    def __enter__(self):
        self._fh = open('/proc/%d/mem' % self._pid)
        return self

    def __exit__(self, *args):
        self._fh.close()
        self._fh = None

    # 0 1| 2 3| 4 5
    def read(self, start, end):
        real_start = int(start / PAGE_SIZE) * PAGE_SIZE
        real_end = int((end + (PAGE_SIZE - 1)) / PAGE_SIZE) * PAGE_SIZE
        self._fh.seek(real_start)
        aligned_result = self._fh.read(real_end - real_start)
        return aligned_result[start - real_start: end - real_start]

    def __getitem__(self, item):
        if isinstance(item, slice):
            item = (item.start, item.stop)
        if isinstance(item, (long, int)):
            item = (item, item + 1)
        assert isinstance(item, (tuple, list)), item
        assert len(item) == 2, item
        return self.read(item[0], item[1])


class Struct(object):
    format = None

    def __new__(cls, *args, **kwargs):
        return args[0]

    @classmethod
    def calcsize(cls):
        return struct.calcsize(cls.format)

    @classmethod
    def unpack(cls, val):
        return struct.unpack(cls.format, val)[0]

class ULong(Struct):
    format = '<Q'

class Long(Struct):
    format = '<q'

class Int(Struct):
    format = '<i'

class Char(Struct):
    format = 'c'

def Stub(length):
    class CharArr(Struct):
        format = 'c' * length
    return [None, CharArr]

def PtrTo(cls):
    class Dummmy(VoidPtr):
        def get_size(self):
            return cls.calcsize()

        def from_mem(self, c):
            return cls.unpack(c)

    return type(cls.__name__ + 'Ptr', (VoidPtr,), dict(Dummmy.__dict__))

class VoidPtr(Struct):
    format = '<Q'

    def __nonzero__(self):
        return self._addr != 0

    def __new__(cls, *args, **kwargs):
        return object.__new__(cls, *args, **kwargs)

    def __init__(self, addr, mr):
        self._mr = mr
        self._addr = addr

    def from_mem(self, c):
        return c

    def get_size(self):
        raise NotImplementedError

    def get_slice(self, start, stop):
        start_byte = start * self.get_size()
        stop_byte  = stop * self.get_size()
        mem = self._mr[self._addr + start_byte: self._addr + stop_byte]
        result = []
        for i in xrange(0, stop_byte - start_byte, self.get_size()):
            result.append(self.from_mem(mem[i: i + self.get_size()]))
        return result

    def __getitem__(self, item):
        start = stop = None
        if isinstance(item, slice):
            start = item.start
            stop = item.stop
        elif isinstance(item, (long, int)):
            return self[item:item + 1][0]
        start = start or 0
        if stop is None:
            raise ValueError("Right bound must be closed")
        return self.get_slice(start, stop)

    def __repr__(self):
        return "<%s(addr=%x)" % (self.__class__.__name__, self._addr)

class CharPtr(PtrTo(Char)):
    def get_slice(self, start, stop):
        return ''.join(super(CharPtr, self).get_slice(start, stop))

ULongPtr = PtrTo(ULong)

class StructPtr(VoidPtr):
    addrs_being_represented = set()
    def get_fields(self):
        raise NotImplementedError

    def alt_repr(self):
        raise NotImplementedError

    def __repr__(self):
        print "Representing %s, addr %x" % (self.__class__.__name__, self._addr)
        if not self._addr:
            return '<%s(NULL)>' % self.__class__.__name__
        else:
            try:
                return self.alt_repr()
            except NotImplementedError:
                pass
            except IOError:
                pass
        try:
            fields = self[0]
        except IOError:
            fields_repr = '(unreadable)'
        else:
            my_key = (type(self), self._addr)
            if my_key in self.addrs_being_represented:
                fields_repr = '(loop)'
            else:
                try:
                    self.addrs_being_represented.add(my_key)
                    for name, field in fields.iteritems():
                        print "REPRESENTING", name
                        if hasattr(field, '_addr'):
                            print "ADDR", hex(field._addr)
                        repr(field)
                    fields_repr = "repr(fields)"
                finally:
                    self.addrs_being_represented.discard(my_key)
        return "<%s(addr=%x, %s)" % (self.__class__.__name__, self._addr, fields_repr)

    def get_size(self):
        result = 0
        for name, field in self.get_fields():
            result += field.calcsize()
        return result

    def offset_of(self, field_name):
        result = 0
        for name, fld in self.get_fields():
            if name == field_name:
                break
            result += fld.calcsize()
        else:
            raise KeyError(field)
        return result

    def from_mem(self, c):
        result = OrderedDict()
        for name, field in self.get_fields():
            sz = field.calcsize()
            value, c = field.unpack(c[:sz]), c[sz:]
            if name is not None:
                result[name] = field(value, self._mr)
        return result

class PyInterpreterStatePtr(StructPtr):
    def get_fields(self):
        return [
            ['next', PyInterpreterStatePtr],
            ['tstate_head',  PyThreadStatePtr],
            ['modules', PyObjectPtr],
            ['sysdict', PyObjectPtr],
            ['builtins', PyObjectPtr],
            ['modules_reloading', PyObjectPtr],
            ['codec_search_path', PyObjectPtr],
            ['codec_search_cache', PyObjectPtr],
            ['codec_error_registry', PyObjectPtr],
        ]


class PyThreadStatePtr(StructPtr):
    def get_fields(self):
        return [
            ['next', PyThreadStatePtr],
            ['interp', PyInterpreterStatePtr],
            ['frame', PyFrameObjectPtr],
            ['recursion_depth', Int],
            ['tracing', Int],
            ['use_tracing', Int],
            ['c_profilefunc', VoidPtr],
            ['c_tracefunc', VoidPtr],
            ['c_profileobj', PyObjectPtr],
            ['c_traceobj', PyObjectPtr],
            ['curexc_type', PyObjectPtr],
            ['curexc_value', PyObjectPtr],
            ['curexc_traceback', PyObjectPtr],
            ['exc_type', PyObjectPtr],
            ['exc_value', PyObjectPtr],
            ['exc_traceback', PyObjectPtr],
            ['dict', PyObjectPtr],
            ['tick_counter', Int],
            ['gilstate_counter', Int],
            ['async_exc', PyObjectPtr],
            ['thread_id', Long],
            ['trash_delete_nesting', Int],
            ['trash_delete_later', PyObjectPtr],
        ]

PyTypeObjectPtr = VoidPtr

class PyObjectPtr(StructPtr):
    def get_fields(self):
        return [
            ['ob_refcnt', ULong],
            ['ob_type', PyTypeObjectPtr]
        ]

class PyVarObjectPtr(PyObjectPtr):
    def get_fields(self):
        return super(PyVarObjectPtr, self).get_fields() + [
            ['ob_size', ULong]
        ]

class PyFrameObjectPtr(PyVarObjectPtr):
    def get_fields(self):
        return super(PyFrameObjectPtr, self).get_fields() + [
            ['f_back', PyFrameObjectPtr],
            ['f_code', PyCodeObjectPtr],
            ['f_builtins', PyObjectPtr],
            ['f_globals', PyObjectPtr],
            ['f_locals', PyObjectPtr],
            ['f_valuestack', VoidPtr], # XXX: Ptr(Ptr(PyObject))
            ['f_stacktop', VoidPtr], # XXX: same
            ['f_trace', PyObjectPtr],
            ['f_exc_type', PyObjectPtr],
            ['f_exc_value', PyObjectPtr],
            ['f_exc_traceback', PyObjectPtr],
            ['f_tstate', PyThreadStatePtr],
            ['f_lasti', Int],
            ['f_lineno', Int],
            ['f_iblock', Int],
            # XXX: Other stuff goes here, but me too lazy
        ]

class PyStringObjectPtr(PyVarObjectPtr):
    def get_fields(self):
        return super(PyStringObjectPtr, self).get_fields() + [
            ['ob_shash', Long],
            ['ob_sstate', Int],
            ['ob_sval', Char]
        ]

    def alt_repr(self):
        return repr(self.to_string())

    def to_string(self):
        size = self[0]['ob_size']
        return CharPtr(self._addr + self.offset_of('ob_sval'), self._mr)[:size]

class PyCodeObjectPtr(PyObjectPtr):
    def get_fields(self):
        return super(PyCodeObjectPtr, self).get_fields() + [
            ['co_argcount', Int],
            ['co_nlocals', Int],
            ['co_stacksize', Int],
            ['co_flags', Int],
            ['co_code', PyObjectPtr],
            ['co_consts', PyObjectPtr],
            ['co_names', PyObjectPtr],
            ['co_varnames', PyObjectPtr],
            ['co_freevars', PyObjectPtr],
            ['co_cellvars', PyObjectPtr],
            ['co_filename', PyStringObjectPtr],
            ['co_name', PyStringObjectPtr],
            ['co_firstlineno', Int],
            Stub(4),
            ['co_lnotab', PyStringObjectPtr],
            # Other uninteresting stuff
        ]

"""
typedef struct {
    PyObject_HEAD
    int co_argcount;        /* #arguments, except *args */
    int co_nlocals;     /* #local variables */
    int co_stacksize;       /* #entries needed for evaluation stack */
    int co_flags;       /* CO_..., see below */
    PyObject *co_code;      /* instruction opcodes */
    PyObject *co_consts;    /* list (constants used) */
    PyObject *co_names;     /* list of strings (names used) */
    PyObject *co_varnames;  /* tuple of strings (local variable names) */
    PyObject *co_freevars;  /* tuple of strings (free variable names) */
    PyObject *co_cellvars;      /* tuple of strings (cell variable names) */
    /* The rest doesn't count for hash/cmp */
    PyObject *co_filename;  /* string (where it was loaded from) */
    PyObject *co_name;      /* string (name, for reference) */
    int co_firstlineno;     /* first source line number */
    PyObject *co_lnotab;    /* string (encoding addr<->lineno mapping) See
                   Objects/lnotab_notes.txt for details. */
    void *co_zombieframe;     /* for optimization only (see frameobject.c) */
    PyObject *co_weakreflist;   /* to support weakrefs to code objects */
} PyCodeObject;
"""

"""
int
PyCode_Addr2Line(PyCodeObject *co, int addrq)
{
    int size = PyString_Size(co->co_lnotab) / 2;
    unsigned char *p = (unsigned char*)PyString_AsString(co->co_lnotab);
    int line = co->co_firstlineno;
    int addr = 0;
    while (--size >= 0) {
        addr += *p++;
        if (addr > addrq)
            break;
        line += *p++;
    }
    return line;
}
"""

def PyCode_Addr2Line(lnotab, last_i, co_firstlineno):
    size = len(lnotab) / 2
    line = co_firstlineno
    addr = 0
    while size - 1 >= 0:
        size -= 1
        addr += ord(lnotab[0]); lnotab = lnotab[1:]
        if addr > last_i:
            break
        line +=  ord(lnotab[0]); lnotab = lnotab[1:]
    return line


def read_proc_maps(pid):
    maps = []
    with open('/proc/%d/maps' % pid, 'rb') as f:
        for line in f:
            entries = line.split()
            if len(entries) >= 5:
                start, end = [int(x, 16) for x in entries[0].split('-')]
                perms = entries[1]
                offset = int(entries[2], 16)
                dev = entries[3]
                inode = int(entries[4])
            filename = None
            if len(entries) in (6, 7):
                filename = entries[5]
            else:
                assert len(entries) == 5, entries

            maps.append(MemMap(start, end, perms, offset, dev, inode, filename))
    return maps

@contextlib.contextmanager
def cmd_as_file(*args, **kwargs):
    kwargs['stdout'] = subprocess.PIPE
    p = subprocess.Popen(*args, **kwargs)
    try:
        yield p.stdout
    finally:
        p.stdout.close()
        p.wait()

def format_frame(frame):
    f_code = frame['f_code'][0]
    co_filename = f_code['co_filename'].to_string()
    co_firstlineno = f_code['co_firstlineno']
    co_lnotab = f_code['co_lnotab'].to_string()
    co_name = f_code['co_name'].to_string()
    line_no = PyCode_Addr2Line(co_lnotab, frame['f_lasti'], co_firstlineno)
    line = linecache.getline(co_filename, line_no)
    return '%s:%s(%d)\n%s' % (
        co_filename, co_name, line_no, line
    )

def format_stack(frame_ptr):
    result = []
    while frame_ptr:
        result.append(format_frame(frame_ptr[0]))
        frame_ptr = frame_ptr[0]['f_back']
    return result[::-1]

def get_interp_head_through_libpython(pid):
    for mapping in read_proc_maps(pid):
        if mapping.filename and 'libpython2.7.so' in mapping.filename and mapping.perms == 'r-xp':
            libpython_mapping = mapping
            debug("Found libpython2.7 library: %s", mapping)
            break
    else:
        warning("Couldn't find libpython2.7.so in memory")
        return

    libpython_filename = libpython_mapping.filename

    with cmd_as_file(['objdump', '--syms', libpython_filename]) as f:
        for line in f:
            if line.strip().endswith('interp_head'):
                debug("Found interp_head symbol: '%s'", ' '.join(line.strip().split()))
                interp_head_offset = int(line.strip().split()[0], 16)
                break
        else:
            warning("Couldn't find interp_head symbol in %s", libpython_filename)
            return
    return libpython_mapping.start + interp_head_offset

def get_interp_head_through_PyInterpreterState_Head(pid):
    for mapping in read_proc_maps(pid):
        if mapping.filename and os.path.basename(mapping.filename) == 'python2.7' and mapping.perms == 'r-xp':
            python_mapping = mapping
            debug("Found python2.7 mapping: %s", mapping)
            break
    else:
        warning("Couldn't find python2.7 executable mapping")
        return

    python_filename = python_mapping.filename

    with cmd_as_file(['objdump', '--dynamic-syms', python_filename]) as f:
        for line in f:
            if line.strip().endswith('PyInterpreterState_Head'):
                debug("Found PyInterpreterState_Head symbol: '%s'", ' '.join(line.strip().split()))
                func_offset = int(line.strip().split()[0], 16)
                break
        else:
            warning("Couldn't find PyInterpreterState_Head symbol in %s", python_filename)
            return

    with MemReader(pid) as mr:
        mov_instr = mr[func_offset: func_offset + 7]
        debug("mov operation: %r %r", mov_instr[:3].encode('hex'), mov_instr[3:].encode('hex'))
        retq_instr = mr[func_offset + 7: func_offset + 8]
        if retq_instr != '\xc3':
            warning("Seems like PyInterpreterState_Head has different length in %s", python_filename)
            return
        mov_operand = struct.unpack('<i', mov_instr[3:])[0]
        interp_head_addr = mov_operand + func_offset + len(mov_instr)
        return interp_head_addr


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('-v', '--verbose', action='store_true', help="Show debug info")
    args = parser.parse_args()
    if args.verbose:
        logging.root.setLevel(logging.DEBUG)
    pid = args.pid

    interp_head_addr = get_interp_head_through_libpython(pid)
    if interp_head_addr is None:
        interp_head_addr = get_interp_head_through_PyInterpreterState_Head(pid)

    if interp_head_addr is None:
        raise RuntimeError("Couldn't locate interp_head variable, is this Python process?")

    debug("interp_head location: %x", interp_head_addr)

    with MemReader(pid) as mr:
        interp_state_addr = ULongPtr(interp_head_addr, mr)[0]
        interp_state = PyInterpreterStatePtr(interp_state_addr, mr)
        # XXX: Why print goes to some incorrect addr?
        #print interp_state[0]['tstate_head'][0]['frame']
        thread_state_ptr = interp_state[0]['tstate_head']
        while thread_state_ptr:
            print "# # # Another thread"
            cur_frame_ptr = thread_state_ptr[0]['frame']
            print ''.join(format_stack(cur_frame_ptr))
            thread_state_ptr = thread_state_ptr[0]['next']
