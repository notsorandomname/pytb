
import pytest
import signal
import textwrap
import contextlib
import sys
from mock import MagicMock
import subprocess
from voodoo.core import Compound
import voodoo.cpython
from voodoo.cpython import Python, PyDictObject
from voodoo.inspecttools import SimpleGdbExecutor, StructHelper

@pytest.fixture
def sample_program_code():
    return textwrap.dedent("""
import time, sys, os
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

import threading
threading.Thread(target=have_a_sleep, kwargs=dict(to_thread_local='t1')).start()
threading.Thread(target=have_a_sleep, kwargs=dict(to_thread_local='t1')).start()
have_a_sleep(notify=True, to_thread_local='main')
    """).strip()

@pytest.fixture(params=['py3k', 'py2'])
def py3k(request):
    return request.param == 'py3k'

@pytest.fixture
def python_cmd(py3k):
    return ['python3' if py3k else 'python']

@pytest.yield_fixture
def sample_program(tmpdir, sample_program_code, python_cmd, py3k):
    path = tmpdir.join('sample_program.py').strpath
    with open(path, 'wb') as f:
        f.write(sample_program_code)
    with subprocess_ctx(python_cmd + [path], stdout=subprocess.PIPE) as p:
        assert p.stdout.read() == 'ready'
        yield p

@contextlib.contextmanager
def get_gdb_executor(request, py3k):
    if py3k:
        executable = request.config.getoption('--python3-dbg')
    else:
        executable = request.config.getoption('--python2-dbg')

    try:
        p = subprocess.Popen([executable, '-c', ''])
    except OSError, ex:
        pytest.skip("while trying to launch %s: %s" % (executable, ex))
    else:
        p.kill()

    with SimpleGdbExecutor([executable]) as sge:
        yield sge

@contextlib.contextmanager
def get_struct_helper(request, py3k):
    with get_gdb_executor(request, py3k) as gdb_executor:
        yield StructHelper(gdb_executor)

@pytest.yield_fixture(params=['struct_helper', 'no_helper'])
def struct_helper(request, py3k):
    if request.param == 'no_helper':
        yield None
    else:
        with get_struct_helper(request, py3k) as struct_helper:
            yield struct_helper

@pytest.yield_fixture
def sample_py(sample_program, py3k, struct_helper):
    with Python(sample_program.pid, py3k=py3k, struct_helper=struct_helper) as py:
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
        for name in dir(voodoo.cpython):
            value = getattr(voodoo.cpython, name)
            if isinstance(value, type) and issubclass(value, Compound):
                cls = value
                if cls.get_c_name() is None or not cls.use_struct_helper():
                    continue
                all_classes.append(cls)
        metafunc.parametrize("cpython_structure_class",
                             all_classes)
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