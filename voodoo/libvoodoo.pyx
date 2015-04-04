import os
import argparse
import linecache
import struct
import contextlib, subprocess
from pprint import pprint
import abc
import collections
import logging
import itertools
from functools import partial
from logging import warning, debug

MemMap = collections.namedtuple("MemMap", "start end perms offset dev inode filename")

class UnreadableMemory(Exception):
    """Memory can't be read"""

class MemReader(object):

    def __init__(self, pid):
        self._pid = pid
        self._fh = None
        # Debug stats
        self._total_read = 0

    def __enter__(self):
        self._fh = open('/proc/%d/mem' % self._pid)
        return self

    def __exit__(self, *args):
        self._fh.close()
        self._fh = None
        debug("Total read %d bytes", self._total_read)

    def _seek(self, position):
        try:
            self._fh.seek(position)
        except OverflowError:
            raise UnreadableMemory(position)

    def _read(self, size):
        try:
            return self._fh.read(size)
        except IOError:
            pos = self._fh.tell()
            raise UnreadableMemory(pos, pos + size)

    def read(self, start, end):
        self._seek(start)
        result = self._read(end - start)
        self._total_read += len(result)
        return result

    def __getitem__(self, item):
        if isinstance(item, slice):
            item = (item.start, item.stop)
        if isinstance(item, (long, int)):
            item = (item, item + 1)
        return self.read(item[0], item[1])

    def get_null_terminated(self, addr, buf_size=256):
        result = []
        self._seek(addr)
        position = addr
        while True:
            try:
                chunk = self._read(buf_size)
            except UnreadableMemory:
                if buf_size == 1:
                    raise
                else:
                    buf_size = max(1, buf_size / 2)
                    self._seek(position)
            else:
                position += buf_size
            try:
                null_position = chunk.index('\x00')
            except ValueError:
                result.append(chunk)
            else:
                result.append(chunk[:null_position])
                break
        return ''.join(result)


class Structured(object):
    """Chunk of memory of some (probably not constant - TODO) size that can be unpacked into some object or structure"""
    def __init__(self, addr, mem, **kwargs):
        super(Structured, self).__init__(**kwargs)
        self._addr = addr
        self._mem = mem

    @classmethod
    def get_size(cls):
        raise NotImplementedError

    def __hash__(self):
        return hash(self._as_hash_tuple())

    def _as_hash_tuple(self):
        return (type(self), self._addr, self._mem)

    def cast_to(self, another_type):
        return another_type(self.get_addr(), self._mem)

    def get_pointer(self):
        return PtrTo(type(self))(addr=None, mem=self._mem, user_value=self.get_addr())

    def as_python_value(self):
        return self

    def get_addr(self):
        if self._addr is None:
            raise ValueError("%s has no addr" % str(self))
        return self._addr

    def _represent_value(self):
        return self._value

    def __repr__(self):
        props = []
        if self._addr is not None:
            props.append('addr=%x' % (self._addr,))
        value_repr = '<unreadable>'
        try:
            value_repr = self._represent_value()
        except UnreadableMemory:
            debug("Failed to represent %s", self.__class__.__name__, exc_info=True)
        if value_repr is not None:
            props.append('value=%s' % (value_repr,))
        return '%s(%s)' % (self.__class__.__name__, ', '.join(props))


class Primitive(Structured):
    """Single primitive object unpacked by struct.unpack"""
    format = None

    def __init__(self, addr, mem, user_value=None, **kwargs):
        super(Primitive, self).__init__(addr, mem, **kwargs)
        if not ((self._addr is not None) ^ (user_value is not None)):
            raise TypeError("You must specify either addr or value, not both (%r, %r)" % (addr, user_value))
        self._user_value = user_value

    @classmethod
    def from_user_value(cls, val, mem):
        return cls(addr=None, mem=mem, user_value=val)

    @property
    def _value(self):
        if self._addr is not None:
            return self.read_from_mem()
        else:
            result = self._user_value
        return result

    @_value.setter
    def _value(self, val):
        if self._addr is not None:
            raise ValueError("Can't modify memory")
        self._user_value = val

    def cast_to(self, another_type):
        return another_type(self._addr, self._mem, user_value=self._user_value)

    def _as_hash_tuple(self):
        return super(Primitive, self)._as_hash_tuple() + (self._user_value,)

    def __add__(self, other):
        result = self.from_user_value(self._value, self._mem)
        result += other
        return result

    def __iadd__(self, other):
        raise NotImplementedError


    @classmethod
    def get_size(cls):
        return struct.calcsize(cls.format)

    def as_python_value(self):
        return self._value

    def __nonzero__(self):
        return bool(self._value)

    def read_from_mem(self):
        val = self._mem[self._addr: self._addr + self.get_size()]
        return struct.unpack(self.format, val)[0]

def create_Primitive(name, format):
    return type(name, (Primitive,), {'format': format})

ULong = create_Primitive('ULong', '<Q')
Long = create_Primitive('Long', '<q')
UInt = create_Primitive('UInt', '<I')
Int = create_Primitive('Int', '<i')
Char = create_Primitive('Char', 'c')

class CompoundMeta(abc.ABCMeta):
    def __init__(cls, name, bases, dct):
        super(CompoundMeta, cls).__init__(name, bases, dct)
        cls._fields_getters = None
        cls._fields_offsets = None
        cls._computed_size = None

class Compound(Structured, collections.Mapping):
    __metaclass__ = CompoundMeta
    def __init__(self, *args, **kwargs):
        if self._fields_getters is None:
            self._init_fields_getters()
        super(Compound, self).__init__(*args, **kwargs)



    @classmethod
    def get_size(cls):
        if cls._computed_size is None:
            cls._init_fields_getters()
        return cls._computed_size

    @classmethod
    def _init_fields_getters(cls):
        getters = {}
        offsets = {}
        offset = 0
        for field_name, field_type in cls.get_fields():
            offsets[field_name] = offset
            getters[field_name] = lambda self_obj, field_type=field_type, offset=offset: field_type(self_obj._addr + offset, self_obj._mem)
            field_size = field_type.get_size()
            offset += field_size
        cls._computed_size = offset
        cls._fields_getters = getters
        cls._fields_offsets = offsets

    def __getitem__(self, item):
        return self._fields_getters[item](self).as_python_value()

    def __iter__(self):
        return iter(self._fields)

    def __len__(self):
        return len(self._fields)

    def __getattr__(self, attr):
        if attr.startswith('_'):
            raise AttributeError(attr)
        try:
            result = self[attr]
        except KeyError:
            raise AttributeError(attr)
        return result

    @classmethod
    def get_fields(cls):
        # [['field', type]]
        return []

    @classmethod
    def offset_of(cls, name):
        return cls._fields_offsets[name]


# def Stub(length):
#     class CharArr(Struct):
#         format = 'c' * length
#     return [None, CharArr]

class Array(Compound):
    value_type = None
    size = 0
    @classmethod
    def get_fields(cls):
        return [[i, cls.value_type] for i in xrange(cls.size)]

    def read_from_mem(self):
        ordered_dct = super(Array, self).read_from_mem()
        result = []
        for i in xrange(len(ordered_dct)):
            result.append(ordered_dct[i])
        return result

def ArrayOf(value_type, size):
    return type(
        value_type.__name__ + 'Arr', (Array,),
        dict(value_type=value_type, size=size))

def Stub(size):
    return [None, ArrayOf(Char, size)]

def PtrTo(value_type, cache={}):
    if value_type not in cache:
        cache[value_type] = type(
            value_type.__name__ + 'Ptr',
            (Ptr,), dict(value_type=value_type)
        )
    return cache[value_type]

class Ptr(ULong):
    value_type = None

    @property
    def _ptr(self):
        """Address where Ptr points to"""
        return self._value

    def as_python_value(self):
        # Pointers must return themselves
        return self

    def deref_boxed(self, as_python_value=False):
        result = self.value_type(self._value, self._mem)
        if as_python_value:
            result = result.as_python_value()
        return result

    def deref(self):
        return self.deref_boxed(as_python_value=True)

    def __iadd__(self, other):
        if isinstance(other, Ptr):
            adding = other._value
        else:
            adding = other * self.deref_boxed().get_size()
        self._value += adding
        return self

    def get_slice_fields(self, start, stop, as_python_values=False):
        result = []
        for i in xrange(start, stop):
            result.append((self + i).deref_boxed(as_python_value=as_python_values))
        return result

    def get_slice(self, start, stop):
        return self.get_slice_fields(start, stop, as_python_values=True)

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

    def _represent_value(self):
        return '0x%x' % self._ptr

class VoidPtrDereference(Exception):
    """Someone tried to dereference a void pointer"""

class VoidPtr(Ptr):
    def deref_boxed(self, *args, **kwargs):
        raise VoidPtrDereference(self)

class CharPtr(Ptr):
    value_type = Char
    def get_slice(self, start, stop):
        return ''.join(super(CharPtr, self).get_slice(start, stop))

    def get_null_terminated(self):
        addr = self._value
        return self._mem.get_null_terminated(addr)

ULongPtr = PtrTo(ULong)

class PyInterpreterState(Compound):
    @classmethod
    def get_fields(cls):
        return [
            ['next', PyInterpreterStatePtr],
            ['tstate_head',  PyThreadStatePtr],
            ['modules', PyDictObjectPtr],
            ['sysdict', PyObjectPtr],
            ['builtins', PyObjectPtr],
            ['modules_reloading', PyObjectPtr],
            ['codec_search_path', PyObjectPtr],
            ['codec_search_cache', PyObjectPtr],
            ['codec_error_registry', PyObjectPtr],
        ]

PyInterpreterStatePtr = PtrTo(PyInterpreterState)

class PyThreadState(Compound):
    @classmethod
    def get_fields(cls):
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

PyThreadStatePtr = PtrTo(PyThreadState)

class PyObject(Compound):
    @classmethod
    def get_fields(cls):
        return [
            ['ob_refcnt', ULong],
            ['ob_type', PyTypeObjectPtr]
        ]

    def get_type_name(self):
        return self.ob_type.deref_boxed().tp_name.get_null_terminated()

    def get_type_hierarchy(self):
        tp_ptr = self.ob_type
        while tp_ptr:
            yield tp_ptr
            tp_ptr = tp_ptr.deref_boxed().tp_base

    def isinstance(self, type_name):
        for type_ptr in self.get_type_hierarchy():
            if type_ptr.deref_boxed().tp_name.get_null_terminated() == type_name:
                return True
        return False

    def as_python_value(self):
        tp_name = self.get_type_name()
        result = self
        if tp_name == 'str':
            result = self.cast_to(PyStringObject).to_string()
        elif tp_name == 'dict':
            result = self.cast_to(PyDictObject).to_dict()
        return result

PyObjectPtr = PtrTo(PyObject)

class PyVarObject(PyObject):
    @classmethod
    def get_fields(cls):
        return super(PyVarObject, cls).get_fields() + [
            ['ob_size', ULong]
        ]

PyVarObjectPtr = PtrTo(PyVarObject)

class PyFrameObject(PyVarObject):
    @classmethod
    def get_fields(cls):
        return super(PyFrameObject, cls).get_fields() + [
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

PyFrameObjectPtr = PtrTo(PyFrameObject)

class PyStringObject(PyVarObject):
    @classmethod
    def get_fields(cls):
        return super(PyStringObject, cls).get_fields() + [
            ['ob_shash', Long],
            ['ob_sstate', Int],
            ['ob_sval', Char]
        ]

    def to_string(self):
        return CharPtr.from_user_value(
            self._addr + self.offset_of('ob_sval'), self._mem
        )[:self.ob_size]

PyStringObjectPtr = PtrTo(PyStringObject)

class PyCodeObject(PyObject):
    @classmethod
    def get_fields(cls):
        return super(PyCodeObject, cls).get_fields() + [
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

PyCodeObjectPtr = PtrTo(PyCodeObject)

class PyTypeObject(PyVarObject):
    @classmethod
    def get_fields(cls):
        return super(PyTypeObject, cls).get_fields() + [
            ['tp_name', CharPtr],
            Stub(8),
            ['tp_basicsize', Int],
            ['tp_itemsize', Int],
            ['tp_dealloc', VoidPtr],
            ['tp_print', VoidPtr],
            ['tp_getattr', VoidPtr],
            ['tp_setattr', VoidPtr],
            ['tp_compare', VoidPtr],
            ['tp_repr', VoidPtr],
            ['tp_as_number', VoidPtr],
            ['tp_as_sequence', VoidPtr],
            ['tp_as_mapping', VoidPtr],
            ['tp_hash', VoidPtr],
            ['tp_call', VoidPtr],
            ['tp_str', VoidPtr],
            ['tp_getattro', VoidPtr],
            ['tp_setattro', VoidPtr],
            ['tp_as_buffer', VoidPtr],
            ['tp_flags', Long],
            ['tp_doc', CharPtr],
            ['tp_traverse', VoidPtr],
            ['tp_clear', VoidPtr],
            ['tp_richcompare', VoidPtr],
            ['tp_weaklistoffset', VoidPtr],
            ['tp_iter', VoidPtr],
            ['tp_iternext', VoidPtr],
            ['tp_methods', VoidPtr],
            ['tp_members', VoidPtr],
            ['tp_getset', VoidPtr],
            ['tp_base', PyTypeObjectPtr],
        ]

PyTypeObjectPtr = PtrTo(PyTypeObject)

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
    f_code = frame['f_code'].deref()
    co_filename = f_code['co_filename'].deref()
    co_firstlineno = f_code['co_firstlineno']
    co_lnotab = f_code['co_lnotab'].deref()
    co_name = f_code['co_name'].deref()
    line_no = PyCode_Addr2Line(co_lnotab, frame['f_lasti'], co_firstlineno)
    line = linecache.getline(co_filename, line_no)
    return '%s:%s(%d)\n%s' % (
        co_filename, co_name, line_no, line
    )

def format_stack(frame_ptr):
    result = []
    while frame_ptr:
        frame = frame_ptr.deref()
        result.append(format_frame(frame))
        frame_ptr = frame['f_back']
    return result[::-1]

def get_symbol_through_libpython(pid, symbol):
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
            line = line.strip().split()
            if line and line[-1] == symbol:
                debug("Found %s symbol: '%s'", symbol, ' '.join(line))
                symbol_offset = int(line[0], 16)
                break
        else:
            warning("Couldn't find %s symbol in %s", symbol, libpython_filename)
            return
    return libpython_mapping.start + symbol_offset

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

class PyDictEntry(Compound):
    @classmethod
    def get_fields(cls):
        return [
            ['me_hash', ULong],
            ['me_key', PyObjectPtr],
            ['me_value', PyObjectPtr],
        ]

PyDictEntryPtr = PtrTo(PyDictEntry)

class PyDictObject(PyObject):
    @classmethod
    def get_fields(cls):
        return super(PyDictObject, cls).get_fields() + [
            ['ma_fill', ULong],
            ['ma_used', ULong],
            ['ma_mask', ULong],
            ['ma_table', PyDictEntryPtr],
            # We are not interested in further fields
            ['ma_lookup', VoidPtr],
            ['ma_smalltable', ArrayOf(PyDictEntry, 8)]
        ]

    def to_dict(self):
        result = {}
        for i in xrange(self.ma_mask + 1):
            entry = self.ma_table[i]
            if entry.me_key and entry.me_value:
                key = entry.me_key.deref()
                if key == '<dummy key>':
                    continue
                result[key] = entry.me_value.deref()
        return result

class PyGC_Head(Compound):
    @classmethod
    def get_fields(cls):
        return [
            ['gc_next', PyGC_HeadPtr],
            ['gc_prev', PyGC_HeadPtr],
            ['gc_refs', ULong],
            Stub(8),
        ]

    def get_object_ptr(self):
        return (self.get_pointer() + 1).cast_to(PyObjectPtr)

PyGC_HeadPtr = PtrTo(PyGC_Head)

class gc_generation(Compound):
    @classmethod
    def get_fields(cls):
        return [
            ['head', PyGC_Head],
            ['threshold', Int],
            ['count', Int],
            Stub(8),
        ]


NUM_GENERATIONS = 3

generations_array = ArrayOf(gc_generation, NUM_GENERATIONS)

PyDictObjectPtr = PtrTo(PyDictObject)

class PyGreenlet(PyObject):
    @classmethod
    def get_fields(cls):
        return super(PyGreenlet, cls).get_fields() + [
            ['stack_start', CharPtr],
            ['stack_stop', CharPtr],
            ['stack_copy', CharPtr],
            ['stack_saved', ULong],
            ['stack_prev', PyGreenletPtr],
            ['parent', PyGreenletPtr],
            ['run_info', PyObjectPtr],
            ['top_frame', PyFrameObjectPtr],
            ['recursion_depth', Int],
            ['weakreflist', PyObjectPtr],
            ['exc_type', PyObjectPtr],
            ['exc_value', PyObjectPtr],
            ['exc_traceback', PyObjectPtr],
            ['dict', PyObjectPtr],
        ]

PyGreenletPtr = PtrTo(PyGreenlet)
