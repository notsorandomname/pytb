import argparse
import logging
from voodoo.utils import  profile
from voodoo.cpython import Python, PyGreenlet


from logging import debug


@profile
def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('-v', '--verbose', action='store_true', help="Show debug info")
    parser.add_argument('-g', '--greenlets', action='store_true', help="Show greenlets stacks")
    # TODO
    #parser.add_argument('-l', '--locals', action='store_true', help="Show frame locals")
    args = parser.parse_args()
    if args.verbose:
        logging.root.setLevel(logging.DEBUG)
    pid = args.pid

    with Python(pid) as py:
        interp_state = py.interp_state
        for thread_state in interp_state.get_thread_states():
            print "### Another thread"
            frame = thread_state.get_frame()
            print ''.join(frame.format_stack())

        if args.greenlets:
            for obj_ptr in py.get_all_objects():
                obj = obj_ptr.deref_boxed()
                if obj.isinstance('greenlet.greenlet'):
                    gr = obj.cast_to(PyGreenlet)
                    top_frame = gr.top_frame.deref_boxed()
                    print "### Another grenlet"
                    print ''.join(top_frame.format_stack())
