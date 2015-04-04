import argparse
import logging
from voodoo.core import  *
from voodoo.cpython import *

from logging import debug

def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('-v', '--verbose', action='store_true', help="Show debug info")
    parser.add_argument('-g', '--greenlets', action='store_true', help="Show greenlets stacks")
    args = parser.parse_args()
    if args.verbose:
        logging.root.setLevel(logging.DEBUG)
    pid = args.pid

    interp_head_addr = get_symbol_through_libpython(pid, 'interp_head')
    if args.greenlets:
        generations_addr_addr = get_symbol_through_libpython(pid, '_PyGC_generation0')
        if generations_addr_addr is None:
            raise RuntimeError("Couldn't locate generations variable")

    if interp_head_addr is None:
        interp_head_addr = get_interp_head_through_PyInterpreterState_Head(pid)

    if interp_head_addr is None:
        raise RuntimeError("Couldn't locate interp_head variable, is this Python process?")

    debug("interp_head location: %x", interp_head_addr)

    with MemReader(pid) as mem:
        interp_head_addr = PtrTo(PyInterpreterStatePtr).from_user_value(interp_head_addr, mem)
        interp_state_ptr = interp_head_addr.deref()
        interp_state = interp_state_ptr.deref()

        thread_state_ptr = interp_state['tstate_head']
        while thread_state_ptr:
            print "# # # Another thread"
            cur_frame_ptr = thread_state_ptr.deref()['frame']
            print ''.join(format_stack(cur_frame_ptr))
            thread_state_ptr = thread_state_ptr.deref()['next']

        if args.greenlets:
            generations_arr = PtrTo(PtrTo(generations_array)).from_user_value(generations_addr_addr, mem).deref()

            obj_ptrs = []
            for generation_no in xrange(NUM_GENERATIONS):
                gen_gc_head_ptr = generations_arr.deref()[generation_no].head.get_pointer()
                gc = gen_gc_head_ptr
                while True:
                    # _PyObject_GC_UNTRACK macro says that
                    # gc_prev always points to some value
                    # there is still a race condition if PyGC_Head
                    # gets free'd and overwritten just before we look
                    # at him
                    gc = gc.deref().gc_prev
                    if gc._value == gen_gc_head_ptr._value:
                        break
                    # XXX: Use thing immediately
                    obj_ptrs.append(gc.deref().get_object_ptr())
            cdef obj_ptr
            for obj_ptr in obj_ptrs:
                obj = obj_ptr.deref_boxed()
                if obj.isinstance('greenlet.greenlet'):
                    gr = obj.cast_to(PyGreenlet)
                    top_frame_ptr = gr.top_frame
                    if top_frame_ptr:
                        print "# # # Anothe grreenlet"
                        print ''.join(format_stack(top_frame_ptr))