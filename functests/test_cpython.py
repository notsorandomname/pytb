
import pytest
import signal
import textwrap
import contextlib
import os
import sys
import tempfile
import shutil
import subprocess
from pytb.core import Compound
import pytb.cpython
from pytb.cpython import Python, PyDictObject
from pytb.inspecttools import SimpleGdbExecutor, StructHelper

@pytest.fixture(scope='module')
def greenlet_program_code():
    return textwrap.dedent("""
    import gevent, sys, os
    def loop_forever(interval, notify=False):
        if notify:
            sys.stdout.write('ready')
            fileno = sys.stdout.fileno()
            sys.stdout.close()
            # closing sys.stdout only marks as closed
            os.close(fileno)
        while True:
            gevent.sleep(interval)
    gevent.spawn(loop_forever, 1)
    gevent.spawn(loop_forever, 1)
    loop_forever(1, notify=True)
""")

@pytest.fixture(scope='module')
def sample_program_code():
    return textwrap.dedent("""
import time, sys, os, threading, gc
def a_sleep(notify):
    if notify:
        sys.stdout.write('ready')
        fileno = sys.stdout.fileno()
        sys.stdout.close()
        # closing sys.stdout only marks as closed
        os.close(fileno)
    while True:
        time.sleep(1)

def have(what, notify):
    return what(notify)

def have_a_sleep(notify=False, to_thread_local=None):
    threading.local().some_val = to_thread_local
    return have(a_sleep, notify=notify)

try:
    chr = unichr
except NameError:
    pass

class Dummy(object): pass

objects = {
    'make_dict_gc_trackable': Dummy,
    'this_is_object_dict': True,
    'simple_string': 'simple_string',
    'simple_unicode_string': u'simple_unicode_string',
    'unicode_string': u'unicode_string' + chr(1234),
    'simple_dict': {'key': 'value'},
}
assert gc.is_tracked(objects)

threading.Thread(target=have_a_sleep, kwargs=dict(to_thread_local='t1')).start()
threading.Thread(target=have_a_sleep, kwargs=dict(to_thread_local='t1')).start()
have_a_sleep(notify=True, to_thread_local='main')
    """).strip()

@pytest.fixture(params=['py2', 'py3k'], scope='module')
def py3k(request):
    return request.param == 'py3k'

@pytest.fixture(scope='module')
def python_cmd(py3k):
    return ['python3' if py3k else 'python']

@pytest.yield_fixture(scope='module')
def module_tmpdir():
    directory = None
    try:
        directory = tempfile.mkdtemp()
        yield directory
    finally:
        if directory is not None:
            shutil.rmtree(directory)

@contextlib.contextmanager
def get_sample_program(program_code, cmd):
    with tempfile.NamedTemporaryFile() as f:
        f.write(program_code)
        f.flush()
        with subprocess_ctx(cmd + [f.name], stdout=subprocess.PIPE) as p:
            yield p

@pytest.yield_fixture(scope='module')
def sample_program(sample_program_code, python_cmd):
    with get_sample_program(sample_program_code, python_cmd) as p:
        assert p.stdout.read() == 'ready'
        yield p

@pytest.yield_fixture(scope='module')
def sample_greenlet_program(greenlet_program_code, python_cmd, py3k):
    if py3k:
        pytest.skip("Greenlets not supported on Python 3 yet")

    p = subprocess.Popen(python_cmd + ['-c', 'import gevent'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.wait() != 0:
        pytest.skip("No gevent found: %s" % ((stdout + '\n' + stderr).strip()))

    with get_sample_program(greenlet_program_code, python_cmd) as p:
        assert p.stdout.read() == 'ready'
        yield p

def get_dbg_executable(py3k, request):
    if py3k:
        dbg_executable = request.config.getoption('--python3-dbg')
    else:
        dbg_executable = request.config.getoption('--python2-dbg')
    try:
        p = subprocess.Popen([dbg_executable, '-c', ''])
    except OSError, ex:
        pytest.skip("while trying to launch %s: %s" % (dbg_executable, ex))
    else:
        p.kill()
    return dbg_executable

@contextlib.contextmanager
def get_gdb_executor(request, py3k):
    dbg_executable = get_dbg_executable(py3k, request)
    with SimpleGdbExecutor([dbg_executable]) as sge:
        yield sge

@contextlib.contextmanager
def get_struct_helper(request, py3k):
    with get_gdb_executor(request, py3k) as gdb_executor:
        yield StructHelper(gdb_executor)

@pytest.yield_fixture(params=['struct_helper', 'no_helper'], scope='module')
def struct_helper(request, py3k):
    if request.param == 'no_helper':
        yield None
    else:
        with get_struct_helper(request, py3k) as struct_helper:
            yield struct_helper

@pytest.yield_fixture(scope='module')
def sample_py(sample_program, py3k, struct_helper):
    with Python(sample_program.pid, py3k=py3k, struct_helper=struct_helper) as py:
        yield py

@pytest.yield_fixture(scope='module')
def sample_greenlet_py(sample_greenlet_program, py3k, struct_helper):
    with Python(sample_greenlet_program.pid, py3k=py3k, struct_helper=struct_helper) as py:
        yield py

@contextlib.contextmanager
def subprocess_ctx(*args, **kwargs):
    p = None
    try:
        p = subprocess.Popen(*args, **kwargs)
        yield p
    finally:
        if p is not None:
            if p.poll() is None:
                try:
                    p.send_signal(signal.SIGKILL)
                except OSError:
                    pass
            p.wait()

def test_get_interp_state_methods(sample_program, py3k):
    with Python(sample_program.pid, py3k=py3k) as py:
        interp_head_through_symbol = py.get_interp_head_addr_through_symbol()
        interp_head_through_func = py.get_interp_head_addr_through_PyInterpreterState_Head()
        assert interp_head_through_func == interp_head_through_symbol

def test_only_one_interp_state(sample_py):
    assert not sample_py.interp_state.next
    assert len(list(sample_py.interp_states)) ==  1

def test_correct_number_of_threads(sample_py):
    assert len(list(sample_py.interp_state.get_thread_states())) == 3

def test_thread_interp_pointer_correct(sample_py):
    for t in sample_py.interp_state.get_thread_states():
        assert t.interp == sample_py.interp_head

def test_thread_dict(sample_py):
    for t in sample_py.interp_state.get_thread_states():
        dict(t.dict.deref_boxed().cast_to(PyDictObject))

def pytest_generate_tests(metafunc):
    if 'cpython_structure' in metafunc.fixturenames:
        all_classes = []
        all_names = []
        for name in dir(pytb.cpython):
            value = getattr(pytb.cpython, name)
            if isinstance(value, type) and issubclass(value, Compound):
                cls = value
                if cls.get_c_name() is None or not cls.use_struct_helper():
                    continue
                all_classes.append(cls)
                all_names.append(cls.__name__)
        metafunc.parametrize("cpython_structure_class",
                             all_classes, ids=all_names)
@pytest.fixture
def cpython_structure(cpython_structure_class, py3k):
    skip_classes = {
        'py3k': set(),
        'py2': set(['PyASCIIObject', 'PyCompactUnicodeObject', 'PyDictKeyEntry', 'PyDictKeysObject', 'PyBytesObject'])
    }
    py_name = 'py3k' if py3k else 'py2'
    skip_set = skip_classes[py_name]

    if cpython_structure_class.get_c_name() in skip_set:
        pytest.skip("Structure %s not tested on %s" % (cpython_structure_class, py_name))
    return cpython_structure_class


def test_struct_helper_for_all_structures(request, cpython_structure, py3k):
    with get_struct_helper(request, py3k) as struct_helper:
        cpython_structure = cpython_structure._customized_from_kwargs(struct_helper=struct_helper, py3k=py3k)
        cpython_structure._lazy_init()
        assert not cpython_structure._fields_offsets_fixups

def test_guessing_python_version(py3k, sample_program):
    assert Python(sample_program.pid)._py3k == py3k

def test_gc_listing_all_objects(sample_py):
    assert list(sample_py.get_all_objects())

@pytest.fixture(scope='module')
def objects_dict(sample_py):
    for obj in sample_py.get_all_objects():
        obj = obj.deref_boxed()
        if not obj.isinstance('dict'):
            continue
        obj = obj.as_python_value()
        if 'this_is_object_dict' in obj:
            return obj
    else:
        raise ValueError("object dict not found")

def test_objects_dict_string(objects_dict):
    assert objects_dict['simple_string'] == 'simple_string'

def test_objects_simple_unicode_string(objects_dict):
    unicode_string = objects_dict['simple_unicode_string']
    assert isinstance(unicode_string, unicode)
    assert unicode_string == u'simple_unicode_string'

def test_objects_unicode_string(objects_dict):
    unicode_string = objects_dict['unicode_string']
    assert isinstance(unicode_string, unicode)
    assert unicode_string == u'unicode_string' + unichr(1234)

def test_objects_dict(objects_dict):
    assert objects_dict['simple_dict'] == {'key': 'value'}

def test_stacktrace(sample_py):
    threads = list(sample_py.interp_state.get_thread_states())
    stacks  = [''.join(thread.frame.deref().format_stack(scriptdir=os.getcwd())) for thread in threads]
    for stack in stacks:
        assert 'return what(notify)' in stack
    main_stack = stacks[-1]
    thread1_stack, thread2_stack = stacks[:-1]
    assert "have_a_sleep(notify=True, to_thread_local='main')" in main_stack
    for stack in [thread1_stack, thread2_stack]:
        assert 'threading.py' in stack

def test_greenlets_get(sample_greenlet_py):
    # 3 greenlets + hub
    assert len(list(sample_greenlet_py.get_greenlets())) == 4

def test_greenlets_stacktrace(sample_greenlet_py):
    has_main_greenlet = 0
    has_sub_greenlet = 0
    for gr in sample_greenlet_py.get_greenlets():
        stacktrace = ''.join(gr.top_frame.deref_boxed().format_stack(scriptdir=os.getcwd()))
        if 'loop_forever(1, notify=True)' in stacktrace:
            has_main_greenlet += 1
        if 'result = self._run(*self.args, **self.kwargs)' in stacktrace:
            assert 'loop_forever' in stacktrace
            has_sub_greenlet += 1
    assert has_main_greenlet == 1
    assert has_sub_greenlet == 2

def communicate(*args, **kwargs):
    kwargs.setdefault('stdout', subprocess.PIPE)
    kwargs.setdefault('stderr', subprocess.PIPE)
    p = subprocess.Popen(*args, **kwargs)
    stdout, stderr = p.communicate()
    output = (stdout + '\n' + stderr).strip()
    if p.wait() != 0:
        raise subprocess.CalledProcessError(p.wait(), args[0], output=output)
    return stdout, stderr

@pytest.fixture
def root_privileges():
    if os.geteuid() != 0:
        pytest.skip("This test needs root privileges for reading proc mem")

@pytest.fixture
def struct_helper_params(py3k, request):
    executable = get_dbg_executable(py3k, request)
    return ['--debug-executable', executable]

def test_launching_pytb(sample_program, root_privileges, struct_helper_params):
    stdout, stderr = communicate(['pytb', str(sample_program.pid)] + struct_helper_params)
    assert "have_a_sleep(notify=True, to_thread_local='main')" in stdout
    assert stdout.count("have(a_sleep, notify=notify)") == 3
    assert not stderr

def test_launching_pytb_greenlets(sample_greenlet_program, root_privileges, struct_helper_params):
    stdout, stderr = communicate(['pytb', str(sample_greenlet_program.pid), '--greenlets'] + struct_helper_params)
    assert "loop_forever(1, notify=True)" in stdout
    assert stdout.count("gevent.sleep(interval)") == 3
    assert not stderr
