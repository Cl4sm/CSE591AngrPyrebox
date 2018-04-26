import logging
import angr

######################################
# futex
######################################

l = logging.getLogger("simuvex.SimProcedures")
#pylint:disable=redefined-builtin,arguments-differ
class futex(angr.SimProcedure):

    IS_SYSCALL = True

    def run(self, uaddr, futex_op, val, timeout, uaddr2, val3):
        op = self.state.se.eval(futex_op)
        if op & 1:  # FUTEX_WAKE
            l.debug('futex(FUTEX_WAKE)')
            return 0
        else:
            l.debug('futex(futex_op=%d)', op)
            return self.state.se.Unconstrained("futex", self.state.arch.bits, key=('api', 'futex'))
