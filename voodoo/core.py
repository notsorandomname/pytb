
import collections
import struct
import abc
import logging
logger = logging.getLogger('voodoo.core')

MemMap = collections.namedtuple("MemMap", "start end perms offset dev inode filename")


class UnreadableMemory(Exception):
    """Memory can't be read"""

class MemReader:
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
        logger.debug("Total read %d bytes", self._total_read)

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
