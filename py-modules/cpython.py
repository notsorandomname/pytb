
import struct
import os
import linecache
import subprocess
import contextlib
from voodoo.utils import profile, cmd_as_file
from voodoo.core import Compound, PtrTo, ArrayOf, Stub, CharPtr, Char, Int, Long, ULong, VoidPtr

from inspecttools import MemReader, read_proc_maps

import logging
logger = logging.getLogger('voodoo.cpython')


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

    def get_thread_states(self, as_python_value=True):
        thread_state_ptr = self.tstate_head
        while thread_state_ptr:
            thread_state = thread_state_ptr.deref_boxed(as_python_value)
            thread_state_ptr = thread_state.next
            yield thread_state

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

    def get_frame(self, as_python_value=True):
        return self.frame.deref_boxed(as_python_value)

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

    @profile
    def get_type_hierarchy(self):
        tp_ptr = self.ob_type
        while tp_ptr:
            yield tp_ptr
            tp_ptr = tp_ptr.deref_boxed().tp_base

    @profile
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

    def format_stack_line(self):
        f_code = self.f_code.deref()
        co_filename = f_code.co_filename.deref()
        co_firstlineno = f_code.co_firstlineno
        co_lnotab = f_code.co_lnotab.deref()
        co_name = f_code.co_name.deref()
        line_no = PyCode_Addr2Line(co_lnotab, self.f_lasti, co_firstlineno)
        line = linecache.getline(co_filename, line_no)
        return '%s:%s(%d)\n%s' % (
            co_filename, co_name, line_no, line
        )

    @staticmethod
    def format_frame_stack(frame_ptr):
        result = []
        while frame_ptr:
            frame = frame_ptr.deref()
            result.append(frame.format_stack_line())
            frame_ptr = frame['f_back']
        return result[::-1]

    def format_stack(self):
        return PyFrameObject.format_frame_stack(self.get_pointer())



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
        sval_addr = self._addr + self.offset_of('ob_sval')
        return self._mem.read(sval_addr, sval_addr + self.ob_size)

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

def get_symbol_through_libpython(pid, symbol):
    for mapping in read_proc_maps(pid):
        if mapping.filename and 'libpython2.7.so' in mapping.filename and mapping.perms == 'r-xp':
            libpython_mapping = mapping
            logger.debug("Found libpython2.7 library: %s", mapping)
            break
    else:
        logger.warning("Couldn't find libpython2.7.so in memory")
        return

    libpython_filename = libpython_mapping.filename

    with cmd_as_file(['objdump', '--syms', libpython_filename]) as f:
        for line in f:
            line = line.strip().split()
            if line and line[-1] == symbol:
                logger.debug("Found %s symbol: '%s'", symbol, ' '.join(line))
                symbol_offset = int(line[0], 16)
                break
        else:
            logger.warning("Couldn't find %s symbol in %s", symbol, libpython_filename)
            return
    return libpython_mapping.start + symbol_offset

def get_symbol_through_static_python(pid, symbol):
    for mapping in read_proc_maps(pid):
        if mapping.filename and os.path.basename(mapping.filename) == 'python2.7' and mapping.perms == 'r-xp':
            python_mapping = mapping
            logger.debug("Found python2.7 mapping: %s", mapping)
            break
    else:
        logger.warning("Couldn't find python2.7 executable mapping")
        return

    python_filename = python_mapping.filename

    with cmd_as_file(['objdump', '--dynamic-syms', python_filename]) as f:
        for line in f:
            line = line.strip().split()
            if line[-1] == symbol:
                logger.debug("Found %s symbol: '%s'", symbol, ' '.join(line))
                symbol_offset = int(line[0], 16)
                break
        else:
            logger.warning("Couldn't find %s symbol in %s", symbol, python_filename)
            return
    return symbol_offset


def get_interp_head_through_PyInterpreterState_Head(pid):
    func_offset = get_symbol_through_static_python(pid, 'PyInterpreterState_Head')
    with MemReader(pid) as mr:
        mov_instr = mr[func_offset: func_offset + 7]
        logger.debug("mov operation: %r %r", mov_instr[:3].encode('hex'), mov_instr[3:].encode('hex'))
        retq_instr = mr[func_offset + 7: func_offset + 8]
        if retq_instr != '\xc3':
            logger.warning("Seems like PyInterpreterState_Head has different length in %s", python_filename)
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


class Python(object):
    def __init__(self, pid):
        self._pid = pid
        self._reinit()

    def _reinit(self):
        self._mem = None
        self._interp_head = None
        self._gc_generations = None

    def __enter__(self):
        self._mem = MemReader(self._pid)
        self._mem.__enter__()
        return self

    def __exit__(self, *args):
        result = self._mem.__exit__(*args)
        self._reinit()
        return result

    @property
    def interp_head(self):
        if self._interp_head is not None:
            return self._interp_head
        interp_head_addr = get_symbol_through_libpython(self._pid, 'interp_head')
        if interp_head_addr is None:
            interp_head_addr = get_interp_head_through_PyInterpreterState_Head(self._pid)
        if interp_head_addr is None:
            raise ValueError("Could not find interp_head symbol for pid %s" % str(self._pid))
        interp_head_addr = PtrTo(
            PyInterpreterStatePtr
        ).from_user_value(interp_head_addr, self._mem)
        interp_head = interp_head_addr.deref()
        self._interp_head = interp_head
        return interp_head

    @property
    def interp_state(self):
        return self.interp_head.deref()

    @property
    def interp_states(self):
        raise NotImplementedError



"""    if args.greenlets:
        generations_addr_addr = get_symbol_through_libpython(pid, '_PyGC_generation0')
        if generations_addr_addr is None:
            raise RuntimeError("Couldn't locate generations variable")


"""