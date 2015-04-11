
import collections
import struct
import abc
import logging
logger = logging.getLogger(__name__)

from .utils import profile

from functools import partial

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
        return None

    def __repr__(self):
        props = []
        if self._addr is not None:
            props.append('addr=%x' % (self._addr,))
        value_repr = '<unreadable>'
        try:
            value_repr = self._represent_value()
        except UnreadableMemory:
            logger.debug("Failed to represent %s", self.__class__.__name__, exc_info=True)
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
    @profile
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

    @profile
    def read_from_mem(self):
        size = self.get_size()
        addr = self._addr
        val = self._mem.read(addr, addr + size)
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
        cls._init_done = False

def field_getter(field_type, offset, compound_obj):
    return field_type(compound_obj._addr + offset, compound_obj._mem)

class Compound(Structured, collections.Mapping):
    __metaclass__ = CompoundMeta
    def __init__(self, *args, **kwargs):
        if not self._init_done:
            self._lazy_init()
        super(Compound, self).__init__(*args, **kwargs)

    @classmethod
    def get_size(cls):
        if not cls._init_done:
            cls._lazy_init()
        return cls._computed_size

    @classmethod
    def _lazy_init(cls):
        getters = collections.OrderedDict()
        offsets = collections.OrderedDict()
        offset = 0
        for field_name, field_type in cls.get_fields():
            offsets[field_name] = offset
            getters[field_name] = partial(field_getter, field_type, offset)
            offset += field_type.get_size()
        cls._computed_size = offset
        cls._fields_getters = getters
        cls._fields_offsets = offsets
        cls._init_done = True

    def __getitem__(self, item):
        return self._getitem_boxed(item).as_python_value()

    def _getitem_boxed(self, item):
        return self._fields_getters[item](self)

    def __iter__(self):
        return iter(self._fields_getters)

    def __len__(self):
        return len(self._fields_getters)

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
        if not cls._init_done:
            cls._lazy_init()
        return cls._fields_offsets[name]

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
        value_type.__name__ + 'Arr%d' % size, (Array,),
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
