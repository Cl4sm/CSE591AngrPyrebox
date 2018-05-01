from __future__ import print_function
from ipython_shell import start_shell
from api import CallbackManager
from api import BP
import pefile
import functools

# Add a requirements list in order to specify which other scripts
# should get loaded before this one

requirements = ["plugins.guest_agent"]

# Callback manager
cm = None
# Printer
pyrebox_print = None

# Global variables
# If we want to keep some global var shared between different callback
# functions that is preserved from call to call, we must define
# it as a global
procs_created = 0
target_procname = ""
target_procpgd = 0
memory = {'0x8048231': '0xdeadbeef'}
regs = {'ac': '0x0',
 'acflag': '0x0',
 'ah': '0xfe',
 'al': '0xb0',
 'ax': '0xfeb0',
 'bh': '0x0L',
 'bl': '0x0',
 'bp': '0x7ffeff58',
 'bx': '0x0',
 'cc_dep1': '0x0',
 'cc_dep2': '0x0',
 'cc_ndep': '0x0',
 'cc_op': '0xf',
 'ch': '0x0',
 'cl': '0x0',
 'cmlen': '0x0L',
 'cmstart': '0x0L',
 'cs': '0x0L',
 'cx': '0x0',
 'd': '0x1',
 'dflag': '0x1',
 'dh': '0xfe',
 'di': '0xff40',
 'dih': '0xff',
 'dil': '0x40',
 'dl': '0xfc',
 'ds': '0x0L',
 'dx': '0xfefc',
 'eax': '0x7ffefeb0',
 'ebp': '0x7ffeff58',
 'ebx': '0x0',
 'ecx': '0x0',
 'edi': '0x7ffeff40',
 'edx': '0x7ffefefc',
 'eflags': '0x44',
 'eip': '0x4011e2',
 'emnote': '0x0L',
 'es': '0x0L',
 'esi': '0x0',
 'esp': '0x7ffefea0',
 'fc3210': '0x0L',
 'flags': '0x44',
 'fpreg': '0x0L',
 'fpround': '0x0',
 'fptag': '0x0L',
 'fpu_regs': '0x0L',
 'fpu_tags': '0x0L',
 'fs': '0xc008',
 'ftop': '0x0',
 'gdt': '0x0L',
 'gs': '0x0',
 'id': '0x1',
 'idflag': '0x1',
 'ip': '0x4011e2',
 'ip_at_syscall': '0x0L',
 'ldt': '0x0L',
 'mm0': '0x0L',
 'mm1': '0x0L',
 'mm2': '0x0L',
 'mm3': '0x0L',
 'mm4': '0x0L',
 'mm5': '0x0L',
 'mm6': '0x0L',
 'mm7': '0x0L',
 'nraddr': '0x0L',
 'pc': '0x4011e2',
 'rflags': '0x44',
 'sc_class': '0x0L',
 'si': '0x0',
 'sih': '0x0',
 'sil': '0x0',
 'sp': '0x7ffefea0',
 'ss': '0x0L',
 'sseround': '0x0',
 'st0': '0x0L',
 'st1': '0x0L',
 'st2': '0x0L',
 'st3': '0x0L',
 'st4': '0x0L',
 'st5': '0x0L',
 'st6': '0x0L',
 'st7': '0x0L',
 'tag0': '0x0',
 'tag1': '0x0',
 'tag2': '0x0',
 'tag3': '0x0',
 'tag4': '0x0',
 'tag5': '0x0',
 'tag6': '0x0',
 'tag7': '0x0',
 'xmm0': '0x0L',
 'xmm1': '0x0L',
 'xmm2': '0x0L',
 'xmm3': '0x0L',
 'xmm4': '0x0L',
 'xmm5': '0x0L',
 'xmm6': '0x0L',
 'xmm7': '0x0L'}



def initialize_callbacks(module_hdl, printer):
    '''
    Initilize callbacks for this module.

    This function will be triggered whenever
    the script is loaded for the first time,
    either with the import_module command,
    or when loaded at startup.
    '''
    # We keep a callback manager as a global var.
    #  --> To access it from any function.
    #  --> Necessary to call cm.clean() from clean() function
    global cm
    global pyrebox_print
    from plugins.guest_agent import guest_agent
    # Initialize printer function (global var), that we can use to print
    # text that is associated to our script
    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    # Initialize the callback manager, and register a couple of named
    # callbacks.
    cm = CallbackManager(module_hdl)
    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="vmi_new_proc")
    cm.add_callback(CallbackManager.REMOVEPROC_CB, remove_proc, name="vmi_remove_proc")
    pyrebox_print("[*]    Initialized callbacks")
    
    filename = None
    with open("filename","rb") as f:
        filename = f.readlines()

    guest_agent.copy_file(filename.strip(), "C:\\Users\\Windows7\\Desktop\\filename.exe")
    guest_agent.execute_file("C:\\Users\\Windows7\\Desktop\\filename.exe")



def clean():
    '''
    Clean up everything.

    This function is called when the script is
    unloaded.

    It is necessary to call the clean() function
    in  the callback manager, that will unregister
    all the registered callbacks. Otherwise, the
    next time the callback is triggered, it will
    try to call to a non existent function and
    PyREbox will crash.

    Here you may clean or log whatever you consider
    necessary.
    '''
    global cm
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")


def find_ep(pgd, proc_name):
    '''Given an address space and a process name, uses pefile module
       to get its entry point
    '''
    global cm
    global loaded_processes
    import api
    for m in api.get_module_list(pgd):
        name = m["name"]
        base = m["base"]
        # size = m["size"]
        if name == proc_name:
            try:
                pe_data = api.r_va(pgd, base, 0x1000)
                pe = pefile.PE(data=pe_data)
                ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                return (base + ep)
            except Exception:
                pyrebox_print("Unable to run pefile on loaded module %s" % name)


def do_copy_execute(line):
    '''Copy a file from host to guest, execute it, and pause VM on its EP - Custom command

       This command will first use the guest agent to copy a file to the guest
       and execute if afterwards.

       This file will be set as target, so that the script will start monitoring
       context changes and retrieve the module entry point as soon as it is
       available in memory. Then it will place a breakpoint on the entry point.
    '''
    global pyrebox_print
    global target_procname
    from plugins.guest_agent import guest_agent

    pyrebox_print("Copying host file to guest, using agent...")

    # Copy the specified file to C:\\temp.exe in the guest
    guest_agent.copy_file(line.strip(), "C:\\Users\\Windows7\\temp.exe")
    # Execute the file
    guest_agent.execute_file("C:\\Users\\Windows7\\temp.exe")
    # stop_agent() does not only kill the agent, but it also
    # disables the agent plugin. Invalid opcodes
    # are not treated as agent commands any more, so this call
    # improves transparency.
    guest_agent.stop_agent()

    # Set target proc name:
    target_procname = "temp.exe"
    pyrebox_print("Waiting for process %s to start\n" % target_procname)


def context_change(target_pgd, target_mod_name, old_pgd, new_pgd):
    '''Callback triggered for every context change
        :param target_pgd: This parameter is inserted using functools.partial (see callback registration)
        :param target_mod_name: This parameter is inserted using functools.partial (see callback registration)
        :param old_pgd: This is the first parameter of the callback
        :param new_pgd: This is the second parameter of the callback
    '''
    global cm
    if target_pgd == new_pgd:
        ep = find_ep(target_pgd, target_mod_name)
        if ep is not None:
            pyrebox_print("The entry point for %s is %x\n" % (target_mod_name, ep))
            cm.rm_callback("context_change")
            # Set a breakpoint on the EP, that will start a shell
            target_procpgd = target_pgd
            bp = BP(ep, target_pgd, func=break_point)#, func=break_point)
            bp.enable()

def break_point(cpu_index, cpu):
    pyrebox_print("BREAKPOINT TRIPPED " + str(cpu_index) + ' ' + str(cpu))
    #set_all_regs(regs, cpu_index)
    #set_all_memory(target_procpgd)
    pyrebox_print("BREAKPOINT TRIPPED " + str(cpu_index) + ' ' + str(cpu))

def set_full_regs(cpu_index, reg_name, value):
    import api
    reg_name = reg_name.upper()
    int_value = int(value.replace('L', ''), 16)
    pyrebox_print("Writing " + value + " to " + reg_name)
    api.w_r(cpu_index, reg_name, int_value)

def set_seg_regs(cpu_index, reg_name, selector, base, limit):
    import api
    reg_name = reg_name.upper()
    int_value = int(value.replace('L', ''), 16)
    pyrebox_print("Writing " + value + " to " + reg_name)
    api.w_sr(cpu_index, reg_name, int_value)

def set_all_regs(registers, cpu_index):
    full_reg_names = ['eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'esi', 'edi', 'eip', 'eflags']
    seg_reg_names = ['es', 'cs', 'ss', 'ds', 'fs', 'gs', 'ldt', 'gdt', 'idt', 'tr']
    #other = ['cr0', 'cr1', 'cr2', 'cr3', 'cr4']
    map(lambda reg: set_full_regs(cpu_index, reg, registers[reg]), full_reg_names)
    #map(lambda reg: set_seg_regs(cpu_index, reg, registers[reg], ???, ???), seg_reg_names)

def set_all_memory(pgd):
    global memory

    pyrebox_print("MEMORY: " + str(memory))
    memory = dict(map(lambda x: (int(x[0], 16), hex_to_bytes(x[1].replace("0x", ""))), memory.iteritems()))
    pyrebox_print("MEMORY: " + str(memory))
    #map(lambda mem: set_memory_virtual(pgd, mem[0], mem[1]), memory.iteritems())
    

def hex_to_bytes(hex_str, endianness=0):
    pyrebox_print("STRING: " + hex_str)
    pyrebox_print("BYTES: " + repr(hex_str.decode("hex")))
    if endianness == 0:
        return hex_str.decode("hex")[::-1]
    else:
        return hex_str.decode("hex")

def set_memory_physical(addr, buf):
    import api
    api.w_pa(addr, buf)

def set_memory_virtual(pgd, addr, buf):
    import api
    api.w_va(pgd, addr, buf)


def new_proc(pid, pgd, name):
    '''
    Process creation callback. Receives 3 parameters:
        :param pid: The pid of the process
        :type pid: int
        :param pgd: The PGD of the process
        :type pgd: int
        :param name: The name of the process
        :type name: str
    '''
    global pyrebox_print
    global procs_created
    global target_procname
    global cm

    pyrebox_print("New process created! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))
    procs_created += 1
    if (name == "test.exe"):
        cm.add_callback(CallbackManager.CONTEXTCHANGE_CB, functools.partial(context_change, pgd, name), name="context_change")

def remove_proc(pid, pgd, name):
    '''
    Process removal callback. Receives 3 parameters:
        :param pid: The pid of the process
        :type pid: int
        :param pgd: The PGD of the process
        :type pgd: int
        :param name: The name of the process
        :type name: str
    '''
    pyrebox_print("Process removed! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))


if __name__ == "__main__":
    # This message will be displayed when the script is loaded in memory
    print("[*] Loading python module %s" % (__file__))
