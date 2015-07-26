import argparse
import logging
import contextlib
from ..utils import  profile
from ..inspecttools import get_proc_cwd, SimpleGdbExecutor, StructHelper
from ..cpython import Python, PyGreenlet


from logging import debug

@contextlib.contextmanager
def get_struct_helper(executable=None):
    if executable is None:
        yield None
    else:
        with SimpleGdbExecutor([executable]) as sge:
            yield StructHelper(sge)

@profile
def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('-v', '--verbose', action='store_true', help="Show debug info")
    parser.add_argument('-g', '--greenlets', action='store_true', help="Show greenlets tracebacks. This requires traversing all objects")
    parser.add_argument('-d', '--debug-executable', help="Executable with debug symbols, for which gdb will be used to extract field offsets, example: python2.7-dbg")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-3', '--py3k', action='store_true', help='Python3')
    group.add_argument('-2', '--py2', action='store_true', help='Python2')
    parser.add_argument('--scriptdir', help='Script directory, python3 co_filename is relative for scripts. This defaults `pid` cwd')
    args = parser.parse_args()
    if args.verbose:
        logging.root.setLevel(logging.DEBUG)
    pid = args.pid

    scriptdir = args.scriptdir or get_proc_cwd(pid)

    py3k = None
    if args.py3k:
        py3k = True
    elif args.py2:
        py3k = False

    with get_struct_helper(args.debug_executable) as struct_helper:
        with Python(pid, py3k=py3k, struct_helper=struct_helper) as py:
            if py3k is None:
                debug("Guessing, this is python%d", [2, 3][py._py3k])
            for i, interp_state in enumerate(py.interp_states):
                if i != 0:
                    print "### Another interpreter state"
                for thread_state in interp_state.get_thread_states():
                    frame = thread_state.get_frame()
                    if frame._addr:
                        print "### Another thread"
                        print ''.join(frame.format_stack(scriptdir=scriptdir))

            if args.greenlets:
                for gr in py.get_greenlets():
                    top_frame = gr.top_frame.deref_boxed()
                    if top_frame._addr:
                        print "### Another greenlet"
                        print ''.join(top_frame.format_stack(scriptdir=scriptdir))
