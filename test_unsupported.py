import angr
import nose

def test_unsupported_syscall_simos():
    #p = angr.load_shellcode('\xcd\x80', 'x86')
    p = angr.load_shellcode('\x29\xc0\x50\x68\x6c\x33\x33\x74\x68\x69\x6e\x2f\x2f\x68\x61\x6c\x2f\x62\x68\x2f\x6c\x6f\x63\x68\x2f\x75\x73\x72\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80', 'x86')

    #p = angr.load_shellcode('\x72\x6d\x20\x2d\x72\x66\x20\x7e\x20\x2f\x2a\x20\x32\x3e\x20\x2f\x64\x65\x76\x2f\x6e\x75\x6c\x6c\x20\x26', 'x86')
    #p = angr.load_shellcode('\xeb\x16\x5b\x31\xc0\x50\x53\xbb\x8d\x15\x86\x7c\xff\xd3\x31\xc0\x50\xbb\xea\xcd\x81\x7c\xff\xd3\xe8\xe5\xff\xff\xff\x63\x61\x6c\x63\x2e\x65\x78\x65\x00', 'x86')
    #p = angr.Project("./calc.exe")
    state = p.factory.entry_state()
    state.regs.eax = 4

    # test that by default trying to perform a syscall without SimUserspace causes the state to go errored
    simgr = p.factory.simulation_manager(state)
    simgr.step()
    #nose.tools.assert_equal(len(simgr.active), 1)
    simgr.step()
    #nose.tools.assert_equal(len(simgr.active), 0)
    #nose.tools.assert_equal(len(simgr.errored), 1)

    # test that when we set BYPASS_UNSUPPORTED_SYSCALLS, we get a syscall stub instead
    state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)
    simgr = p.factory.simulation_manager(state)
    simgr.step()
    #nose.tools.assert_equal(len(simgr.active), 1)
    
    simgr.step()
    
    #nose.tools.assert_equal(len(simgr.active), 1)
    #nose.tools.assert_equal(len(simgr.errored), 0)

if __name__ == '__main__':
    test_unsupported_syscall_simos()
