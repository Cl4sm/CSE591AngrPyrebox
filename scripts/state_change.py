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


def do_custom_command_example(line):
    ''' Example of custom command. This first line will be shown as command description when %list_commands is called.

        The rest of this docstring will be shown if we call
        help(**command**) from the ipython command line.

        If we declare any function with the "do_" prefix,
        it will be added automagically as a shell command,
        ignoring the "do_" prefix.

        These functions must have an argument that will
        receive the command line arguments as a string.
    '''
    global pyrebox_print
    global procs_created
    pyrebox_print("The arguments for this custom command are: %s" % line)
    pyrebox_print("I am a script, and the number of processes created is %d\n" % procs_created)


def do_set_target(line):
    '''Set target process - Custom command

       Set a target process name. When a process with this name is created,
       the script will start monitoring context changes and retrieve
       the module entry point as soon as it is available in memory. Then
       it will place a breakpoint on the entry point.
    '''
    global pyrebox_print
    global target_procname
    target_procname = line.strip()
    pyrebox_print("Waiting for process %s to start\n" % target_procname)


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
            bp = BP(ep, target_pgd)
    #        bp.enable()

def break_point(cpu_index, cpu):
    pyrebox_print("BREAKPOINT TRIPPED")

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
        bp = BP(0x4014e ,pgd, size=0x1000, func=break_point)
        bp.enable()
        pyrebox_print("Set Breakpoint " + hex(bp.get_addr()))
    # For instance, we can start the shell whenever a process is created
    #ep = find_ep(pgd, name)
    #if ep is not None:
    #    pyrebox_print("The entry point for %s is %x\n" % (name, ep))
    #    # Set a breakpoint on the EP, that will start a shell
    #    bp = BP(ep, pgd)
    #    #bp.enable()

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
