
import struct
import os
import linecache
import subprocess
import contextlib
from pytb.utils import profile, cmd_as_file
from pytb.core import (
    Compound, PtrTo, ArrayOf, Stub, CharPtr, Char,
    Int, Long, ULong, VoidPtr, UInt, IntPtr
)

from inspecttools import MemReader, read_proc_maps, get_symbol, SymbolNotFound

import logging
logger = logging.getLogger('pytb.cpython')


class PyInterpreterState(Compound):
    py3k = False
    @classmethod
    def get_fields(cls):
        return [
            ['next', PyInterpreterStatePtr],
            ['tstate_head',  PyThreadStatePtr],
            ['modules', PyDictObjectPtr],
            ['modules_by_index', PyDictObjectPtr] * cls.py3k,
            ['sysdict', PyObjectBasePtr],
            ['builtins', PyObjectBasePtr],
            ['importlib', PyObjectBasePtr] * cls.py3k,
            ['modules_reloading', PyObjectBasePtr] * (not cls.py3k),
            ['codec_search_path', PyObjectBasePtr],
            ['codec_search_cache', PyObjectBasePtr],
            ['codec_error_registry', PyObjectBasePtr],
        ]

    def get_thread_states(self, as_python_value=True):
        thread_state_ptr = self.tstate_head
        while thread_state_ptr:
            thread_state = thread_state_ptr.deref_boxed(as_python_value)
            thread_state_ptr = thread_state.next
            yield thread_state

PyInterpreterStatePtr = PtrTo(PyInterpreterState)

class PyThreadState(Compound):
    py3k = False

    @classmethod
    def get_fields(cls):
        return [
            ['prev', PyThreadStatePtr] * cls.py3k,
            ['next', PyThreadStatePtr],
            ['interp', PyInterpreterStatePtr],
            ['frame', PyFrameObjectPtr],
            ['recursion_depth', Int],
            ['overflowed', Char] * cls.py3k,
            ['recursion_critical', Char] * cls.py3k,
            Stub(2) * cls.py3k,
            ['tracing', Int],
            ['use_tracing', Int],
            Stub(4) * (not cls.py3k),
            ['c_profilefunc', VoidPtr],
            ['c_tracefunc', VoidPtr],
            ['c_profileobj', PyObjectBasePtr],
            ['c_traceobj', PyObjectBasePtr],
            ['curexc_type', PyObjectBasePtr],
            ['curexc_value', PyObjectBasePtr],
            ['curexc_traceback', PyObjectBasePtr],
            ['exc_type', PyObjectBasePtr],
            ['exc_value', PyObjectBasePtr],
            ['exc_traceback', PyObjectBasePtr],
            ['dict', PyObjectBasePtr],
            ['tick_counter', Int] * (not cls.py3k),
            ['gilstate_counter', Int],
            Stub(4) * cls.py3k,
            ['async_exc', PyObjectBasePtr],
            ['thread_id', Long],
            ['trash_delete_nesting', Int],
            Stub(4),
            ['trash_delete_later', PyObjectBasePtr],
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

class PyObjectBase(Compound):
    py3k = False
    @classmethod
    def use_struct_helper(cls):
        return cls._customization_base is not PyObjectBase

    @classmethod
    def get_c_name(cls):
        if cls._customization_base is PyObjectBase:
            return None
        else:
            return super(PyObjectBase, cls).get_c_name()

    @classmethod
    def get_c_field_name(cls, field):
        if cls.py3k:
            if field in ['ob_refcnt', 'ob_type']:
                return 'ob_base->' + field
        return super(PyObjectBase, cls).get_c_field_name(field)

    @classmethod
    def get_fields(cls):
        if cls.py3k:
            return [['ob_base', PyObject]]
        else:
            return PyObject.get_fields()

    @property
    def pyobj_head(self):
        if self.py3k:
            return self.ob_base
        else:
            return self

    @property
    def type(self):
        return self.pyobj_head.ob_type.deref_boxed()

    @profile
    def isinstance(self, type_name):
        for tp in self.type.hierarchy:
            if tp.name == type_name:
                return True
        return False

    def as_python_value(self):
        tp_name = self.type.name
        result = self
        if tp_name == 'str':
            if self.py3k:
                result = unicode(self.cast_to(PyUnicodeObject).to_string())
            else:
                result = self.cast_to(PyStringObject).to_string()
        elif tp_name == 'unicode':
            result = self.cast_to(PyUnicodeObject).to_string()
        elif tp_name == 'bytes':
            result = self.cast_to(PyStringObject).to_string()
        elif tp_name == 'dict':
            result = self.cast_to(PyDictObject).to_dict()
        return result

PyObjectBasePtr = PtrTo(PyObjectBase)

class PyVarObject(PyObjectBase):
    py3k = False
    @classmethod
    def get_fields(cls):
        return super(PyVarObject, cls).get_fields() + [
            ['ob_size', ULong]
        ]

    @classmethod
    def get_c_field_name(cls, field):
        if cls.py3k:
            if cls._customization_base is not PyVarObject:
                if field in ['ob_size']:
                    return 'ob_base->' + field
        return super(PyVarObject, cls).get_c_field_name(field)

PyVarObjectPtr = PtrTo(PyVarObject)

class PyFrameObject(PyVarObject):
    py3k = False
    @classmethod
    def get_fields(cls):
        return super(PyFrameObject, cls).get_fields() + [
            ['f_back', PyFrameObjectPtr],
            ['f_code', PyCodeObjectPtr],
            ['f_builtins', PyDictObjectPtr],
            ['f_globals', PyDictObjectPtr],
            ['f_locals', PyObjectBasePtr],
            ['f_valuestack', VoidPtr], # XXX: Ptr(Ptr(PyObjectBase))
            ['f_stacktop', VoidPtr], # XXX: same
            ['f_trace', PyObjectBasePtr],
            ['f_exc_type', PyObjectBasePtr],
            ['f_exc_value', PyObjectBasePtr],
            ['f_exc_traceback', PyObjectBasePtr],
            ['f_tstate', PyThreadStatePtr] * (not cls.py3k),
            ['f_gen', PyObjectBasePtr] * cls.py3k,
            ['f_lasti', Int],
            ['f_lineno', Int],
            ['f_iblock', Int],
            # XXX: Other stuff goes here, but me too lazy
        ]

    def get_lineno(self):
        f_code = self.f_code.deref_boxed()
        co_firstlineno = f_code.co_firstlineno
        co_lnotab = f_code.co_lnotab.deref()
        return PyCode_Addr2Line(co_lnotab, self.f_lasti, co_firstlineno)

    def format_stack_line(self, scriptdir):
        f_code = self.f_code.deref()
        co_filename = f_code.co_filename.deref()
        co_name = f_code.co_name.deref()
        filename = os.path.join(scriptdir, co_filename)
        lineno = self.get_lineno()
        line = linecache.getline(filename, lineno)
        return '%s:%s(%d)\n\t%s\n' % (
            filename, co_name, lineno, line.strip()
        )

    @staticmethod
    def format_frame_stack(frame_ptr, scriptdir):
        result = []
        while frame_ptr:
            frame = frame_ptr.deref()
            result.append(frame.format_stack_line(scriptdir))
            frame_ptr = frame.f_back
        return result[::-1]

    def format_stack(self, scriptdir=None):
        if scriptdir is None:
            raise TypeError("Script co_filename are relative to script location")
        if scriptdir is None:
            scriptdir = os.getcwd()
        return PyFrameObject.format_frame_stack(self.get_pointer(), scriptdir=scriptdir)



PyFrameObjectPtr = PtrTo(PyFrameObject)

class _PyStringObject(PyVarObject):
    py3k = False
    @classmethod
    def use_struct_helper(cls):
        return cls._customization_base is _PyStringObject

    @classmethod
    def get_fields(cls):
        return super(_PyStringObject, cls).get_fields() + [
            ['ob_shash', Long],
            ['ob_sstate', Int] * (not cls.py3k),
            ['ob_sval', Char]
        ]

    def to_string(self):
        sval_addr = self._addr + self.offset_of('ob_sval')
        return self._mem.read(sval_addr, sval_addr + self.ob_size)

class PyStringObject(_PyStringObject):
    py3k = False
    @classmethod
    def use_struct_helper(cls):
        return not cls.py3k

PyStringObjectPtr = PtrTo(PyStringObject)

# py3k only

class PyBytesObject(_PyStringObject):
    py3k = True

PyBytesObjectPtr = PtrTo(PyBytesObject)

class PyASCIIObject(PyObjectBase):
    @classmethod
    def get_fields(cls):
        return super(PyASCIIObject, cls).get_fields() + [
            ['length', ULong],
            ['hash', ULong],
            ['state', UInt],
            Stub(4),
            ['wstr', VoidPtr],
        ]

class PyCompactUnicodeObject(PyASCIIObject):
    @classmethod
    def get_fields(cls):
        return super(PyCompactUnicodeObject, cls).get_fields() + [
            ['utf8_length', ULong],
            ['utf8', CharPtr],
            ['wstr_length', ULong],
        ]

    @classmethod
    def get_c_field_name(cls, field):
        super_name = super(PyCompactUnicodeObject, cls).get_c_field_name(field)
        if field not in ['utf8_length', 'utf8', 'wstr_length']:
            super_name = '_base->' + super_name
        return super_name
# XXX: Use py3k_only instead of multiplying
class PyUnicodeObject(PyCompactUnicodeObject):
    py3k = False
    @classmethod
    def get_fields(cls):
        if cls.py3k:
            return PyCompactUnicodeObject._customized(cls._customization_dict).get_fields() + [
                ['data', CharPtr], # actually there is a union here
            ]
        else:
            return PyObjectBase._customized(cls._customization_dict).get_fields() + [
                ['length', ULong],
                ['str', IntPtr],
                ['hash', Long],
                ['defenc', PyObjectBasePtr],
            ]

    @classmethod
    def get_c_field_name(cls, field):
        super_name = super(PyUnicodeObject, cls).get_c_field_name(field)
        if not cls.py3k:
            super_name = field
        else:
            if field in ['data']:
                super_name = field
            else:
                super_name = '_base->' + super_name
        return super_name

    def to_string(self):
        if self.py3k:
            return self.to_string_v3()
        else:
            return self.to_string_v2()

    def to_string_v2(self):
        return unicode(''.join(unichr(x) for x in self.str[:self.length]))

    def to_string_v3(self):
        # XXX: Legacy strings?
        state = self.state
        interned = state & 0b11
        state >>= 2
        kind = state & 0b111
        state >>= 3
        compact = state & 0b1
        state >>= 1
        ascii = state & 0b1
        state >>= 1
        ready = state & 0b1
        state >>= 1

        if kind not in (1, 2, 4):
            raise NotImplementedError("kind", kind)
        if ascii == 1:
            data_offset = PyASCIIObject.get_size()
        else:
            data_offset = PyCompactUnicodeObject.get_size()

        buf_size = kind * self.length
        buf_addr = self._addr + data_offset

        buf = self._mem.read(buf_addr, buf_addr + buf_size)

        if kind == 2:
            buf = buf.decode('utf-16')
        elif kind == 4:
            buf = buf.decode('utf-32')

        return buf

class PyCodeObject(PyObjectBase):
    py3k = False
    @classmethod
    def get_fields(cls):
        return super(PyCodeObject, cls).get_fields() + [
            ['co_argcount', Int],
            ['co_kwonlyargcount', Int] * cls.py3k,
            ['co_nlocals', Int],
            ['co_stacksize', Int],
            ['co_flags', Int],
            Stub(4) * cls.py3k,
            ['co_code', PyObjectBasePtr],
            ['co_consts', PyObjectBasePtr],
            ['co_names', PyObjectBasePtr],
            ['co_varnames', PyObjectBasePtr],
            ['co_freevars', PyObjectBasePtr],
            ['co_cellvars', PyObjectBasePtr],
            ['co_cell2arg', CharPtr] * cls.py3k,
            ['co_filename', PyStringObjectPtr],
            ['co_name', PyStringObjectPtr],
            ['co_firstlineno', Int],
            Stub(4),
            ['co_lnotab', PyStringObjectPtr],
            # Other uninteresting stuff
        ]

PyCodeObjectPtr = PtrTo(PyCodeObject)

class PyTypeObject(PyVarObject):
    @property
    def name(self):
        return self.tp_name.get_null_terminated()

    @property
    def hierarchy(self):
        tp_ptr = self.get_pointer()
        while tp_ptr:
            tp = tp_ptr.deref_boxed()
            yield tp
            tp_ptr = tp.tp_base


    @classmethod
    def get_fields(cls):
        return super(PyTypeObject, cls).get_fields() + [
            ['tp_name', CharPtr],
            ['tp_basicsize', Int],
            Stub(4),
            ['tp_itemsize', Int],
            Stub(4),
            ['tp_dealloc', VoidPtr],
            ['tp_print', VoidPtr],
            ['tp_getattr', VoidPtr],
            ['tp_setattr', VoidPtr],
            ['tp_compare', VoidPtr] * (not cls.py3k),
            ['tp_reserved', VoidPtr] * cls.py3k,
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

class PyDictEntry(Compound):
    py3k = False
    @classmethod
    def use_struct_helper(cls):
        return False
    @classmethod
    def get_fields(cls):
        return [
            ['me_hash', ULong],
            ['me_key', PyObjectBasePtr],
            ['me_value', PyObjectBasePtr],
        ]

class PyDictKeyEntry(PyDictEntry):
    pass

PyDictEntryPtr = PtrTo(PyDictEntry)
PyDictKeyEntryPtr = PtrTo(PyDictKeyEntry)


class PyDictKeysObject(Compound):
    @classmethod
    def get_fields(cls):
        return [
            ['dk_refcnt', ULong],
            ['dk_size', ULong],
            ['dk_lookup', VoidPtr],
            ['dk_usable', ULong],
            # repeated dk_size times
            ['dk_entries', PyDictKeyEntry],
        ]

PyDictKeysObjectPtr = PtrTo(PyDictKeysObject)

class PyDictObject(PyObjectBase):
    py3k = False
    @classmethod
    def get_fields(cls):
        py2_version = [
            ['ma_fill', ULong],
            ['ma_used', ULong],
            ['ma_mask', ULong],
            ['ma_table', PyDictEntryPtr],
            # We are not interested in further fields
            ['ma_lookup', VoidPtr],
            ['ma_smalltable', ArrayOf(PyDictEntry, 8)]
        ]
        py3_version = [
            ['ma_used', ULong],
            ['ma_keys', PyDictKeysObjectPtr],
            ['ma_values', PtrTo(PyObjectBasePtr)]
        ]
        return super(PyDictObject, cls).get_fields() + (
            py3_version if cls.py3k else py2_version
        )

    @staticmethod
    def entries_to_dict(entries_ptr, size, values_ptr, allow_dummy=False, py3k=False, as_python_value=True):
        result = {}
        for i in xrange(size):
            entry = entries_ptr[i]
            if entry.me_key and entry.me_value:
                key = entry.me_key.deref_boxed()
                key_python = key.as_python_value()
                if allow_dummy:
                    if py3k:
                        if key.type.name ==  "<dummy key> type":
                            continue
                    elif key_python == '<dummy key>':
                        continue
                if as_python_value:
                    key = key_python
                if values_ptr:
                    value = values_ptr + i
                else:
                    value = entry.me_value
                result[key] = value.deref_boxed(as_python_value)
        return result

    def to_dict(self, as_python_value=True):
        if self.py3k:
            return self.to_dict_v3(as_python_value)
        else:
            return self.to_dict_v2(as_python_value)

    def to_dict_v2(self, as_python_value):
        return PyDictObject.entries_to_dict(
            self.ma_table, self.ma_mask + 1, values_ptr=None,
            allow_dummy=True, py3k=False,
            as_python_value=as_python_value)

    def to_dict_v3(self, as_python_value):
        keys_obj = self.ma_keys.deref_boxed()
        return PyDictObject.entries_to_dict(
            keys_obj.dk_entries.get_pointer(),
            keys_obj.dk_size, values_ptr=self.ma_values,
            allow_dummy=False, py3k=True,
            as_python_value=as_python_value,
        )

PyDictObjectPtr = PtrTo(PyDictObject)


class PyModuleObject(PyObjectBase):
    @classmethod
    def get_fields(cls):
        return super(PyModuleObject, cls).get_fields() + [
            ['md_dict', PyDictObjectPtr],
        ]

PyModuleObjectPtr = PtrTo(PyModuleObject)

class PyGC_Head(Compound):
    py3k = False
    @classmethod
    def get_fields(cls):
        return [
            ['gc_next', PyGC_HeadPtr],
            ['gc_prev', PyGC_HeadPtr],
            ['gc_refs', ULong],
            Stub(8) * (not cls.py3k),
        ]

    @classmethod
    def get_c_field_name(cls, field):
        return 'gc->' + field

    def get_object_ptr(self):
        return (self.get_pointer() + 1).cast_to(PyObjectBasePtr)

PyGC_HeadPtr = PtrTo(PyGC_Head)

class gc_generation(Compound):
    py3k = False
    @classmethod
    def get_fields(cls):
        return [
            ['head', PyGC_Head],
            ['threshold', Int],
            ['count', Int],
            Stub(8) * (not cls.py3k),
        ]

    @classmethod
    def use_struct_helper(cls):
        return False


NUM_GENERATIONS = 3

GC_generations_array = ArrayOf(gc_generation, NUM_GENERATIONS)

class PyGreenlet(PyObjectBase):
    @classmethod
    def get_fields(cls):
        return super(PyGreenlet, cls).get_fields() + [
            ['stack_start', CharPtr],
            ['stack_stop', CharPtr],
            ['stack_copy', CharPtr],
            ['stack_saved', ULong],
            ['stack_prev', PyGreenletPtr],
            ['parent', PyGreenletPtr],
            ['run_info', PyObjectBasePtr],
            ['top_frame', PyFrameObjectPtr],
            ['recursion_depth', Int],
            ['weakreflist', PyObjectBasePtr],
            ['exc_type', PyObjectBasePtr],
            ['exc_value', PyObjectBasePtr],
            ['exc_traceback', PyObjectBasePtr],
            ['dict', PyObjectBasePtr],
        ]

    @classmethod
    def use_struct_helper(cls):
        return False # XXX: Think how to use it here

PyGreenletPtr = PtrTo(PyGreenlet)


class Python(object):
    def __init__(self, pid, py3k=None, struct_helper=None):
        self._pid = pid
        if py3k is None:
            py3k = self.guess_py3k(pid)
        self._py3k = py3k
        self._struct_helper = struct_helper
        self._reinit()

    @property
    def _customization_dict(self):
        return {'py3k': self._py3k, 'struct_helper': self._struct_helper}

    def _reinit(self):
        self._mem = None
        self._interp_head_addr = None
        self._gc_generations = None

    def __enter__(self):
        self._mem = MemReader(self._pid)
        self._mem.__enter__()
        return self

    @staticmethod
    def guess_py3k(pid):
        """Try to guess if this is python3"""
        try:
            get_symbol(pid, 'PyUnicode_AsASCIIString')
        except SymbolNotFound:
            return False
        else:
            return True

    def __exit__(self, *args):
        result = self._mem.__exit__(*args)
        self._reinit()
        return result

    def _get_interp_head(self, interp_head_addr):
        interp_head_addr = PtrTo(PtrTo(
            PyInterpreterState
        ))._customized(self._customization_dict).from_user_value(interp_head_addr, self._mem)
        return interp_head_addr.deref()

    @property
    def interp_head(self):
        return self._get_interp_head(self.interp_head_addr)

    @property
    def interp_head_addr(self):
        """Returns PtrTo(PtrTo(PyInterpreterState)) value"""
        if self._interp_head_addr is not None:
            return self._interp_head_addr
        try:
            interp_head_addr = self.get_interp_head_addr_through_symbol()
        except SymbolNotFound:
            logger.debug("Could not find interp_head symbol")
            # Hard way
            interp_head_addr = self.get_interp_head_addr_through_PyInterpreterState_Head()
        self._interp_head_addr = interp_head_addr
        return interp_head_addr

    @property
    def interp_state(self):
        return self.interp_head.deref_boxed()

    @property
    def interp_states(self):
        ptr = self.interp_head
        while ptr:
            interp_state = ptr.deref_boxed()
            yield interp_state
            ptr = interp_state.next

    @property
    def gc_generations(self):
        if self._gc_generations is not None:
            return self._gc_generations
        generations_addr_addr = get_symbol(self._pid, '_PyGC_generation0')
        generations_arr = PtrTo(PtrTo(GC_generations_array._customized(self._customization_dict))).from_user_value(
            generations_addr_addr, self._mem).deref().deref()
        self._gc_generations = [generations_arr[i] for i in xrange(NUM_GENERATIONS)]
        return self._gc_generations

    def get_all_objects(self):
        "Return pointers to all GC tracked objects"
        for i, generation in enumerate(self.gc_generations):
            generation_head_ptr = pygc_head_ptr = generation.head.get_pointer()
            generation_head_addr = generation_head_ptr._value
            while True:
                # _PyObjectBase_GC_UNTRACK macro says that
                # gc_prev always points to some value
                # there is still a race condition if PyGC_Head
                # gets free'd and overwritten just before we look
                # at him
                pygc_head_ptr = pygc_head_ptr.deref().gc_next
                if pygc_head_ptr._value == generation_head_addr:
                    break
                yield pygc_head_ptr.deref().get_object_ptr()

    def get_greenlets(self):
        for obj_ptr in self.get_all_objects():
            obj = obj_ptr.deref_boxed()
            if obj.isinstance('greenlet.greenlet'):
                yield obj.cast_to(PyGreenlet)

    def get_interp_head_addr_through_symbol(self):
        return get_symbol(self._pid, 'interp_head')

    def get_interp_head_addr_through_PyInterpreterState_Head(self):
        # Let's disassemble PyInterpreterState_Head func
        # It should look like
        # mov someval, reg # <addr>
        # retq
        func_offset = get_symbol(self._pid, 'PyInterpreterState_Head')
        func = self._mem[func_offset: func_offset + 8]
        with cmd_as_file(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '/dev/stdin'], stdin=func) as f:
            lines = f.readlines()[-2:]
            if len(lines) < 2 or 'ret' not in lines[-1] or 'mov' not in lines[-2] or '#' not in lines[-2]:
                raise BadAssembly(lines)
            absolute_addr = lines[-2].strip().split('#')[-1]
            try:
                absolute_addr = int(absolute_addr, 16)
            except ValueError:
                raise BadAssembly(str(exc), absolute_addr)
            return absolute_addr + func_offset

class BadAssembly(Exception):
    pass

