import argparse
import logging
from ..utils import  profile
from ..inspecttools import get_proc_cwd
from ..cpython import Python, PyGreenlet


from logging import debug


@profile
def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('-v', '--verbose', action='store_true', help="Show debug info")
    parser.add_argument('-g', '--greenlets', action='store_true', help="Show greenlets tracebacks. This requires traversing all objects")
    parser.add_argument('-l', '--locals', action='store_true', help="Show frame locals")
    parser.add_argument('-3', '--py3k', action='store_true', help='Python3')
    parser.add_argument('--scriptdir', help='Script directory, python3 co_filename is relative for scripts. This defaults `pid` cwd')
    args = parser.parse_args()
    if args.verbose:
        logging.root.setLevel(logging.DEBUG)
    pid = args.pid

    scriptdir = args.scriptdir or get_proc_cwd(pid)

    with Python(pid, py3k=args.py3k) as py:
        for i, interp_state in enumerate(py.interp_states):
            from ..cpython import PyModuleObject
            print dict(interp_state.modules.deref())['__main__'].cast_to(PyModuleObject).md_dict.deref()
            if i != 0:
                print "### Another interpreter state"
            for thread_state in interp_state.get_thread_states():
                print "### Another thread"
                frame = thread_state.get_frame()
                print ''.join(frame.format_stack(scriptdir=scriptdir))

        if args.greenlets:
            for obj_ptr in py.get_all_objects():
                obj = obj_ptr.deref_boxed()
                if obj.isinstance('greenlet.greenlet'):
                    gr = obj.cast_to(PyGreenlet)
                    top_frame = gr.top_frame.deref_boxed()
                    if top_frame._addr:
                        print "### Another greenlet"
                        print ''.join(top_frame.format_stack(scriptdir=scriptdir))
