import lldb

def get_inst(target, thread):
    frame = thread.GetSelectedFrame()
    insn = target.ReadInstructions(frame.addr, 1)[0]
    return insn

def get_pc(thread):
    frame = thread.GetSelectedFrame()
    return frame.GetPC()

def suspend_threads_escape_select_thread(process, flag):
    select_thread = process.GetSelectedThread()
    if flag:
        for item in process:
            if select_thread.GetThreadID() == item.GetThreadID():
                pass
            else:
                print('Suspend thread : {}'.format(item))
                item.Suspend()
    else:
        print('Resume all threads.')
        for item in process:
            item.Resume()

def step_func(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    suspend_threads_escape_select_thread(process, True)
    start_num_frames = thread.GetNumFrames()
    runned_lst = set(list())
    while True:
        inst = get_inst(target, thread)
        pc = get_pc(thread)
        if pc not in runned_lst:
            runned_lst.add(pc)
            print("%x: %s" % (pc, inst))
        op = inst.GetMnemonic(target)
        if op == "ret":
            print("return")
            break
        elif op == "bl" or op == "blr":
            next_pc = pc + 4
            bp = target.BreakpointCreateByAddress(next_pc)
            bp.SetThreadID(thread.GetThreadID())
            print("continue")
            process.Continue()
        else:
            thread.StepInstruction(True)
        if thread.GetNumFrames() < start_num_frames:
            print("return to parent")
            break
    stream = lldb.SBStream()
    print(stream.GetData())

def __lldb_init_module (debugger, dict):
    debugger.HandleCommand('command script add -f %s.step_func sf' % __name__)
    print("import done")

