
import collections
import logging
import os

logger = logging.getLogger(__name__)

from .utils import profile, cmd_as_file

MemMap = collections.namedtuple("MemMap", "start end perms offset dev inode filename")

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
        logger.debug("Total read %d bytes", self._total_read)

    @profile
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

    @profile
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

def get_all_file_symbols(filename, cache={}):
    if filename not in cache:
        symbols = {}
        for additional_args in [[], ['--dynamic']]:
            with open(os.devnull, 'wb') as devnull:
                with cmd_as_file(['nm'] + additional_args + [filename], stderr=devnull) as f:
                    for line in f:
                        line = line.strip().split()
                        if len(line) == 3:
                            symbols[line[-1]] = int(line[0], 16)
        cache[filename] = symbols
    return cache[filename]

def find_symbol_in_file(filename, symbol, cache={}):
    return get_all_file_symbols(filename).get(symbol)

def get_pid_executable(pid):
    return '/proc/%d/exe' % pid

def find_symbol(pid, symbol):
    """Return [(MemMap, value), ...]"""
    for mapping in read_proc_maps(pid):

        if not mapping.filename or not os.path.exists(mapping.filename):
            continue
        # We're interested only in the main mapping for each library
        # It looks like executable bit and 0 offset suits our needs
        if 'x' not in mapping.perms or mapping.offset:
            continue

        offset = find_symbol_in_file(mapping.filename, symbol)

        # This is probably horribly wrong, we say
        # that symbol has absolute value if it is located in executable
        absolute = os.path.samefile(mapping.filename, get_pid_executable(pid))

        if offset is not None:
            yield mapping, offset, absolute

class SymbolNotFound(ValueError):
    'symbol not found'

def get_symbol(pid, symbol):
    for mapping, offset, absolute in find_symbol(pid, symbol):
        if not absolute:
            offset += mapping.start
        return offset
    raise SymbolNotFound(symbol)
