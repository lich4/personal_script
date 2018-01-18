#used to follow instructions when debug
import idaapi
x=0
while x<100:
    idaapi.step_over()
    GetDebuggerEvent(WFNE_SUSP, -1) 
    rv = idaapi.regval_t()
    idaapi.get_reg_val('EIP',rv)
    print GetDisasm(rv.ival)
    if GetMnem(rv.ival) == "retn":
    break
    x = x + 1