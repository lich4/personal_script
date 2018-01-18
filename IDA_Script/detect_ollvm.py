#This script is for un-ollvm
 #the core is to link between flag set and flag compare positions
 import copy

MAXTURN = 60    # we trace 30 instructions once at most 


 def determine_ifjmp(inst, freg, compstat):
     #compstat   None => not two regs        1 => both reg None      2 => one reg None       3 => none None
     #signed jump
     #return   3:should jmp  2:should not jmp  1:do not known
     if inst == "BGT":#signed
         if freg[1] != None:
             if freg[1] > 0:
                 return 3
             else:
                 return 2
     elif inst == "BLT" or inst == "BMI":#signed
         if freg[1] != None:
             if freg[1] < 0:
                 return 3
             else:
                 return 2
     elif inst == "BLE":#signed
         if freg[1] != None:
             if freg[1] <= 0:
                 return 3
             else:
                 return 2
     elif inst == "BGE" or inst == "BPL":#signed
         if freg[1] != None:
             if freg[1] >= 0:
                 return 3
             else:
                 return 2
     #
     elif inst == "BNE":
         if freg[0] != None:
             if freg[0] != 0:
                 return 3
             else:
                 return 2
     elif inst == "BEQ":
         if freg[0] != None:
             if freg[0] == 0:
                 return 3
             else:
                 return 2
     #unsigned jump
     elif inst == "BHI":#unsigned
         if freg[0] != None:
             if freg[0] > 0:
                 return 3
             else:
                 return 2
     elif inst == "BHIS" or inst == "BCS":#unsigned
         if freg[0] != None:
             if freg[0] >= 0:
                 return 3
             else:
                 return 2
     elif inst == "BLO" or inst == "BCC":#unsigned
         if freg[0] != None:
             if freg[0] < 0:
                 return 3
             else:
                 return 2      
     elif inst == "BLOS" or inst == "BLS":#unsigned
         if freg[0] != None:
             if freg[0] <= 0:
                 return 3
             else:
                 return 2
     #compare ollvm-flag reg with unknown reg,
     if compstat == 2:
         return 2
     return 1


 changelist = {}
 def roll_back():
     #this function uses only when we find out the modify on jmp is wrong
     for addr in changelist:
         PatchByte(addr, changelist[addr])
 def clear():
     changelist = {}
     
 def trace_dest(addr, regs, freg):
     #this function find out what inst finally reach in a ollvm-switch(the real functionally code)
     #regs : registers stored before jump
     #addr : current address
     #begin: block begin
     #end  : block end
     
     #freg store compare inst result (unsigned/signed)
     print "--------------trace %x" % addr
     
     endaddr = None
     alreadyrun = []
     passjumpnum = 0
     
     curaddr = addr
     count = 0
     canhandle = False
     while count < MAXTURN:
         print hex(curaddr),GetDisasm(curaddr),regs
         canhandle = False
         if curaddr in alreadyrun:
             endaddr = None
             break
         alreadyrun.append(curaddr)
         mnem = GetMnem(curaddr)
         if mnem == "LDR":
             if GetOpType(curaddr, 0) == o_reg:
                 if GetOpType(curaddr, 1) == o_mem:
                     regs[GetOpnd(curaddr, 0)] = Dword(GetOperandValue(curaddr, 1))
                     canhandle = True
                     curaddr = curaddr + allinsts[curaddr]
         elif mnem == "MOV":
             if GetOpType(curaddr, 0) == o_reg:
                 if GetOpType(curaddr, 1) == o_reg:
                     regs[GetOpnd(curaddr, 0)] = regs[GetOpnd(curaddr, 1)]
                     canhandle = True
                     curaddr = curaddr + allinsts[curaddr]
         elif mnem == "CMP":
             freg = [None, None]
             if GetOpType(curaddr, 0) == o_reg and GetOpType(curaddr, 1) == o_reg:
                 f, s = GetOpnd(curaddr, 0), GetOpnd(curaddr, 1)
                 if regs[f] != None and regs[s] != None:
                     freg[0] = regs[f] - regs[s]
                     tmpf = regs[f]
                     if regs[f] > 0x80000000:
                         tmpf = regs[f] - 0x100000000
                     tmps = regs[s]
                     if regs[s] > 0x80000000:
                         tmps = regs[s] - 0x100000000
                     freg[1] = tmpf - tmps
                     canhandle = True
                     curaddr = curaddr + allinsts[curaddr]
         elif mnem == "BLX":#we cannot let execute any real code
             canhandle = False
         elif mnem == "B":
             inst = GetDisasm(curaddr).split(' ')[0]
             if inst == "B":
                 canhandle = True
                 curaddr = GetOperandValue(curaddr, 0)
             elif inst in ["BGT", "BLT", "BLE", "BGE", "BNE", "BEQ", "BHI", "BHIS", "BLO", "BLS",  "BLOS", "BCS", "BCC", "BMI", "BPL"]:
                 ret = determine_ifjmp(inst, freg, -1) # -1 => set unknown compare to unknown result 
                 if ret == 3:
                     passjumpnum = passjumpnum + 1
                     canhandle = True
                     curaddr = GetOperandValue(curaddr, 0)
                 elif ret == 2:
                     passjumpnum = passjumpnum + 1
                     canhandle = True
                     curaddr = curaddr + allinsts[curaddr]
                 else:
                     canhandle = False
             else:
                 print "unhandle %x" % curaddr  
         else:
             canhandle = False
         if not canhandle:
             if passjumpnum >= 1:
                 endaddr = curaddr
             break
         count = count - 1
     if endaddr != None:
         #endaddr2 = trace_dest(endaddr, regs, freg)
         #if endaddr2 != None:
             #endaddr = endaddr2
         print "from %x to %x"%(addr, endaddr)
     return endaddr


 def try_trace_fix_ollvm(begin, end):
     #this function find out all jmp trunk for region and modify them
     #these regs specific for ollvm
     print "begin=0x%x, end=0x%x" % (begin, end)
     
     regs = {"R0":None, "R1":None, "R2":None, "R3":None, "R4":None, "R5":None, "R6":None, 
         "R7":None, "R8":None, "R9":None, "R10":None, "R11":None, "R12":None}
     freg = [None, None]
     compstat = None
     #   None => not two regs        1 => both reg None      2 => one reg None       3 => none None
     curaddr = begin
     count = 0
     if FT_TYPE == FT_ELF:
         while curaddr >= begin and curaddr <= end and count < MAXTURN:
             #print hex(curaddr), GetDisasm(curaddr), regs, compstat
             mnem = GetMnem(curaddr)
             if mnem == "LDR":
                 if GetOpType(curaddr, 0) == o_reg:
                     if GetOpType(curaddr, 1) == o_mem:
                         regs[GetOpnd(curaddr, 0)] = Dword(GetOperandValue(curaddr, 1))
                         #if LDR R,=flag is the last inst, we see if can change to jump inst
                         if curaddr == end - 2: 
                             print "trace branch +5 %x" % curaddr 
                             dst = trace_dest(curaddr + 2, copy.copy(regs), copy.copy(freg))
                             if dst != None:
                                 #we trace this route and modify the jump
                                 x = (dst - curaddr - 4) / 2
                                 if x >= 0x7ff or x <= -0x7ff:
                                     print "error here"
                                 else:
                                     obyte = (x & 0x7FF) + 0xE000
                                     if curaddr not in changelist:
                                         #if we haven't modify yet
                                         changelist[curaddr] = Byte(curaddr)
                                         changelist[curaddr+1] = Byte(curaddr+1)
                                         PatchByte(curaddr, obyte & 0xff)
                                         PatchByte(curaddr + 1, (obyte >> 8) & 0xff)
                                         print "patch %x from %x to %x" %(curaddr, changelist[curaddr], obyte)
                     else:
                         regs[GetOpnd(curaddr, 0)] = None
                 curaddr = curaddr + allinsts[curaddr]
             elif mnem == "MOV":
                 if GetOpType(curaddr, 0) == o_reg:
                     if GetOpType(curaddr, 1) == o_reg:
                         regs[GetOpnd(curaddr, 0)] = regs[GetOpnd(curaddr, 1)]
                     else:
                         regs[GetOpnd(curaddr, 0)] = None
                 curaddr = curaddr + allinsts[curaddr]
             elif mnem == "CMP":
                 freg = [None, None]
                 compstat = None
                 if GetOpType(curaddr, 0) == o_reg and GetOpType(curaddr, 1) == o_reg:
                     f, s = GetOpnd(curaddr, 0), GetOpnd(curaddr, 1)
                     if regs[f] != None and regs[s] != None:
                         compstat = 3
                         freg[0] = regs[f] - regs[s]
                         tmpf = regs[f]
                         if regs[f] > 0x80000000:
                             tmpf = regs[f] - 0x100000000
                         tmps = regs[s]
                         if regs[s] > 0x80000000:
                             tmps = regs[s] - 0x100000000
                         freg[1] = tmpf - tmps
                     elif regs[f] != None or regs[s] != None:
                         compstat = 2
                     else:
                         compstat = 1
                 else: 
                     compstat = None
                 curaddr = curaddr + allinsts[curaddr]
             elif mnem == "BLX":#skip this
                 regs["R0"] = None
                 curaddr = curaddr + allinsts[curaddr]
             elif mnem == "B":
                 #if we can ensure at the circumstance of regs, the brach Go only one way then we break here, or else we follow more branchs
                 objaddr = GetOperandValue(curaddr, 0)
                 inst = GetDisasm(curaddr).split(' ')[0]
                 if inst == "B":
                     print "trace branch +4 %x" % curaddr 
                     dst = trace_dest(objaddr, copy.copy(regs), copy.copy(freg))
                     if dst != None:
                         #we trace this route and modify the jump
                         x = (dst - curaddr - 4) / 2
                         if x >= 0x7ff or x <= -0x7ff:
                             print "error here"
                         else:
                             obyte = (x & 0x7FF) + 0xE000
                             if curaddr not in changelist:
                                 #if we haven't modify yet
                                 changelist[curaddr] = Byte(curaddr)
                                 changelist[curaddr+1] = Byte(curaddr+1)
                                 PatchByte(curaddr, obyte & 0xff)
                                 PatchByte(curaddr + 1, (obyte >> 8) & 0xff)
                                 print "patch %x from %x to %x" %(curaddr, changelist[curaddr], obyte)
                     curaddr = objaddr
                 elif inst in ["BGT", "BLT", "BLE", "BGE", "BNE", "BEQ", "BHI", "BHIS", "BLS","BLO", "BLOS", "BCS", "BCC", "BMI", "BPL"]:
                     ret = determine_ifjmp(inst, freg, compstat)
                     #return   3:should jmp  2:should not jmp  1:do not known
                     #this branch is certainly be passed under current circumstance
                     if ret == 3:
                         print "trace branch +3 %x" % curaddr
                         dst = trace_dest(objaddr, copy.copy(regs), copy.copy(freg))
                         if dst != None:
                             #we trace this route and modify the jump
                             x = (dst - curaddr - 4) / 2
                             if x >= 0xff or x <= -0xff:
                                 print "error here"
                             else:
                                 obyte = x & 0xFF
                                 if curaddr not in changelist:
                                     #if we haven't modify yet
                                     changelist[curaddr] = Byte(curaddr)
                                     PatchByte(curaddr, obyte)
                                     print "patch %x from %x to %x" %(curaddr, changelist[curaddr], obyte)
                         #stop here
                         break
                     #this branch is certainly not be passed under current circumstance
                     elif ret == 2:
                         print "trace branch +2 %x" % curaddr
                         curaddr = curaddr + allinsts[curaddr]
                     #this branch is unknown whether be passed under current circumstance
                     elif ret == 1:
                         print "trace branch +0 %x" % curaddr
                         dst = trace_dest(objaddr, copy.copy(regs), copy.copy(freg))
                         if dst != None:
                             #we trace this route and modify the jump
                             x = (dst - curaddr - 4) / 2
                             if x >= 0xff or x <= -0xff:
                                 print "error here"
                             else:
                                 obyte = x & 0xFF
                                 if curaddr not in changelist:
                                     #if we haven't modify yet
                                     changelist[curaddr] = Byte(curaddr)
                                     PatchByte(curaddr, obyte)
                                     print "patch %x from %x to %x" %(curaddr, changelist[curaddr], obyte)            
                         curaddr = curaddr + allinsts[curaddr]
                 else:
                     print "unhandle b:", GetDisasm(curaddr)
             else:
                 print "skip handle:", GetDisasm(curaddr)
                 curaddr = curaddr + allinsts[allinsts]
             count = count + 1
     elif FT_TYPE == FT_MACHO:
         while curaddr >= begin and curaddr <= end and count < MAXTURN:
             #print hex(curaddr), GetDisasm(curaddr), regs, compstat
             mnem = GetMnem(curaddr)
             if mnem == "LDR":
                 if GetOpType(curaddr, 0) == o_reg:
                     if GetOpType(curaddr, 1) == o_mem:
                         regs[GetOpnd(curaddr, 0)] = Dword(GetOperandValue(curaddr, 1))
                         #if LDR R,=flag is the last inst, we see if can change to jump inst
                         if curaddr == end - 2: 
                             print "trace branch +5 %x" % curaddr 
                             dst = trace_dest(curaddr + 2, copy.copy(regs), copy.copy(freg))
                             if dst != None:
                                 #we trace this route and modify the jump
                                 x = (dst - curaddr - 4) / 2
                                 if x >= 0x7ff or x <= -0x7ff:
                                     print "error here"
                                 else:
                                     obyte = (x & 0x7FF) + 0xE000
                                     if curaddr not in changelist:
                                         #if we haven't modify yet
                                         changelist[curaddr] = Byte(curaddr)
                                         changelist[curaddr+1] = Byte(curaddr+1)
                                         PatchByte(curaddr, obyte & 0xff)
                                         PatchByte(curaddr + 1, (obyte >> 8) & 0xff)
                                         print "patch %x from %x to %x" %(curaddr, changelist[curaddr], obyte)
                     else:
                         regs[GetOpnd(curaddr, 0)] = None
                 curaddr = curaddr + allinsts[curaddr]
             elif mnem == "MOV":
                 if GetOpType(curaddr, 0) == o_reg:
                     if GetOpType(curaddr, 1) == o_reg:
                         regs[GetOpnd(curaddr, 0)] = regs[GetOpnd(curaddr, 1)]
                     else:
                         regs[GetOpnd(curaddr, 0)] = None
                 curaddr = curaddr + allinsts[curaddr]
             elif mnem == "CMP":
                 freg = [None, None]
                 compstat = None
                 if GetOpType(curaddr, 0) == o_reg and GetOpType(curaddr, 1) == o_reg:
                     f, s = GetOpnd(curaddr, 0), GetOpnd(curaddr, 1)
                     if regs[f] != None and regs[s] != None:
                         compstat = 3
                         freg[0] = regs[f] - regs[s]
                         tmpf = regs[f]
                         if regs[f] > 0x80000000:
                             tmpf = regs[f] - 0x100000000
                         tmps = regs[s]
                         if regs[s] > 0x80000000:
                             tmps = regs[s] - 0x100000000
                         freg[1] = tmpf - tmps
                     elif regs[f] != None or regs[s] != None:
                         compstat = 2
                     else:
                         compstat = 1
                 else: 
                     compstat = None
                 curaddr = curaddr + allinsts[allinsts]
             elif mnem == "BLX":#skip this
                 regs["R0"] = None
                 curaddr = curaddr + allinsts[curaddr]
             elif mnem == "B":
                 #if we can ensure at the circumstance of regs, the brach go only one way then we break here, or else we follow more branchs
                 objaddr = GetOperandValue(curaddr, 0)
                 inst = GetDisasm(curaddr).split(' ')[0]
                 if inst == "B":
                     print "trace branch +4 %x" % curaddr 
                     dst = trace_dest(objaddr, copy.copy(regs), copy.copy(freg))
                     if dst != None:
                         #we trace this route and modify the jump
                         x = (dst - curaddr - 4) / 2
                         if x >= 0x7ff or x <= -0x7ff:
                             print "error here"
                         else:
                             obyte = (x & 0x7FF) + 0xE000
                             if curaddr not in changelist:
                                 #if we haven't modify yet
                                 changelist[curaddr] = Byte(curaddr)
                                 changelist[curaddr+1] = Byte(curaddr+1)
                                 PatchByte(curaddr, obyte & 0xff)
                                 PatchByte(curaddr + 1, (obyte >> 8) & 0xff)
                                 print "patch %x from %x to %x" %(curaddr, changelist[curaddr], obyte)
                     curaddr = objaddr
                 elif inst in ["BGT", "BLT", "BLE", "BGE", "BNE", "BEQ", "BHI", "BHIS", "BLS","BLO", "BLOS", "BCS", "BCC", "BMI", "BPL"]:
                     ret = determine_ifjmp(inst, freg, compstat)
                     #return   3:should jmp  2:should not jmp  1:do not known
                     #this branch is certainly be passed under current circumstance
                     if ret == 3:
                         print "trace branch +3 %x" % curaddr
                         dst = trace_dest(objaddr, copy.copy(regs), copy.copy(freg))
                         if dst != None:
                             #we trace this route and modify the jump
                             x = (dst - curaddr - 4) / 2
                             if x >= 0xff or x <= -0xff:
                                 print "error here"
                             else:
                                 obyte = x & 0xFF
                                 if curaddr not in changelist:
                                     #if we haven't modify yet
                                     changelist[curaddr] = Byte(curaddr)
                                     PatchByte(curaddr, obyte)
                                     print "patch %x from %x to %x" %(curaddr, changelist[curaddr], obyte)
                         #stop here
                         break
                     #this branch is certainly not be passed under current circumstance
                     elif ret == 2:
                         print "trace branch +2 %x" % curaddr
                         curaddr = curaddr + allinsts[curaddr]
                     #this branch is unknown whether be passed under current circumstance
                     elif ret == 1:
                         print "trace branch +0 %x" % curaddr
                         dst = trace_dest(objaddr, copy.copy(regs), copy.copy(freg))
                         if dst != None:
                             #we trace this route and modify the jump
                             x = (dst - curaddr - 4) / 2
                             if x >= 0xff or x <= -0xff:
                                 print "error here"
                             else:
                                 obyte = x & 0xFF
                                 if curaddr not in changelist:
                                     #if we haven't modify yet
                                     changelist[curaddr] = Byte(curaddr)
                                     PatchByte(curaddr, obyte)
                                     print "patch %x from %x to %x" %(curaddr, changelist[curaddr], obyte)            
                         curaddr = curaddr + allinsts[curaddr]
                 else:
                     print "unhandle b:", GetDisasm(curaddr)
             else:
                 print "skip handle:", GetDisasm(curaddr)
                 curaddr = curaddr + allinsts[allinsts]
             count = count + 1

def get_jmplist(funcaddr):
     #this function find out all addr list to deal with 
     tmp = set([])
     #for Android elf
     addr = funcbegin
     while addr < funcend:
         if GetMnem(addr) == "B":
             objaddr = GetOperandValue(addr, 0)
             if objaddr > funcbegin and objaddr < funcend:
                 tmp.add(objaddr)
         addr = addr + allinsts[addr]
     alllabel.append(funcaddr)
     for addr in tmp:
         alllabel.append(addr)
     alllabel.append(funcend)
     alllabel.sort()

def check_ollvm(addr):
     if GetDisasm(addr) == GetDisasm(addr+2): #arm or thumb ?
         return False
     begin = GetFunctionAttr(addr, FUNCATTR_START)
     end = GetFunctionAttr(addr, FUNCATTR_END)
     ollvm_flag_num = 0
     
     l_insts = []
     l_allinsts = {}
     for item in FuncItems(begin):
         l_insts.append(item)
     l_insts.append(end)
     for i in range(0, len(l_insts) - 1):
         l_allinsts[l_insts[i]] = l_insts[i + 1] - l_insts[i]
     
     #for android elf
     if FT_TYPE == FT_ELF:
         addr = begin
         while addr < end:
             inst = GetDisasm(addr).split(' ')[0]
             if inst == "LDR" and GetOpType(addr, 0) == o_reg and GetOpType(addr, 1) == o_mem:
                 val = Dword(GetOperandValue(addr,1))
                 if val >= 0x1000000 and (val>>16) != 0xFFFF:
                     ollvm_flag_num = ollvm_flag_num + 1
             addr = addr + l_allinsts[addr]
     #for iOS mach-o
     else:
         addr = begin
         while addr < end:
             inst = GetDisasm(addr).split(' ')[0]
             if inst == "MOV" and GetOpType(addr, 0) == o_reg and GetOpType(addr, 1) == o_imm:
                 val = GetOperandValue(addr,1)
                 if val >= 0x1000000 and (val>>16) != 0xFFFF:
                     ollvm_flag_num = ollvm_flag_num + 1 
             addr = addr + l_allinsts[addr]
     return ollvm_flag_num > ((end - begin) / 20)
     
 def get_funcset():
     addr = PrevFunction(0xffffffff)
     if FT_TYPE == FT_ELF:
         while addr < 0xffffffff:
             if SegName(addr) in [".text"]:
                 funcset.append(addr)
             addr = PrevFunction(addr)
     if FT_TYPE == FT_MACHO:
         while addr < 0xffffffff:
             if SegName(addr) in ["__text"] and GetFunctionName(addr).find("[") == -1:
                 funcset.append(addr)
             addr = PrevFunction(addr)       
     
 def get_all_instructions():
     #this function get all disassemble lines for a function
     insts = []
     for item in FuncItems(funcbegin):
         insts.append(item)
     insts.append(funcend)
     for i in range(0, len(insts) - 1):
         allinsts[insts[i]] = insts[i + 1] - insts[i]

def find_ios_ollvm_branches(funcaddr):
     funcbegin = GetFunctionAttr(funcaddr, FUNCATTR_START)
     funcend = GetFunctionAttr(funcaddr, FUNCATTR_END)
     ollvmmap = {}
     insts = []
     for item in FuncItems(funcbegin):
         insts.append(item)
     for i in range(0, len(insts)):
         curaddr = insts[i]
         inst = GetDisasm(curaddr).split(' ')[0]
         if inst.startswith("BEQ"):
             beaddr = insts[i-3]
             if GetMnem(beaddr) == "MOV" and GetOpType(beaddr, 1) == o_imm:
                 ollvmmap[GetOperandValue(beaddr, 1)] = GetOperandValue(curaddr, 0)
     for i in ollvmmap:
         print "%x-%x"%(i,ollvmmap[i])  

def set_jump(srcaddr, dstaddr):
     curaddr = srcaddr
     x = (dstaddr - curaddr - 4) / 2
     if x >= 0x7ff or x <= -0x7ff:
         print "error here"
     else:
         obyte = (x & 0x7FF) + 0xE000
         if curaddr not in changelist:
             PatchByte(curaddr, obyte & 0xff)
             PatchByte(curaddr + 1, (obyte >> 8) & 0xff)  
   
 FT_MACHO = 25  #FT_ELF = 18 
 FT_TYPE = GetShortPrm(INF_FILETYPE)
 ARCH = GetCharPrm(INF_PROCNAME)
         
 if __name__ == "__main__":
     if ARCH != "ARM":
         raise
     if FT_TYPE != FT_MACHO and FT_TYPE != FT_ELF:
         raise
     funcaddr = 0x72A8A8  #an address in function
     funcbegin = GetFunctionAttr(funcaddr, FUNCATTR_START)
     funcend = GetFunctionAttr(funcaddr, FUNCATTR_END)
     #alllabel is each entry for ollvm flag set  (such as R0=0x88991122)
     alllabel = []
     #insts is all instructions in a function, addr<->inst len
     allinsts = {}
     #all function in this file
     funcset = []
     get_funcset()
     get_all_instructions()
     get_funcset()
