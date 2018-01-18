from idaapi import *
def get_all_structs():
    #tranverse structures
    idx  = GetFirstStrucIdx()
    while idx != idaapi.BADADDR:
        sid = GetStrucId(idx)
        print "%d\t%x\t%s\t" % (idx, sid, GetStrucName(sid))  
        m = GetFirstMember(sid)
        while (m != -1 and m != idaapi.BADADDR):
            name = GetMemberName(sid, m)
            if name:
                print "\t+%x\t%x\t%s" % (m, GetMemberSize(sid, m), name)
            m = GetStrucNextOff(sid, m)    
        idx = GetNextStrucIdx(idx)

def get_all_localtypes():
    #traverse local types
    ml=GetMaxLocalType()
    for i in range(1, ml):
        print i, GetLocalType(i, 6)

def disasm_func(addr):
    #disassemble a function
    begin=GetFunctionAttr(addr,FUNCATTR_START)
    end=GetFunctionAttr(addr,FUNCATTR_END)
    while begin < end:
        print GetDisasm(begin)
        begin = begin + decode_insn(begin)

#for sk3wldbg
def setbpatcall(funcaddr):
    start=GetFunctionAttr(funcaddr,FUNCATTR_START)
    end=GetFunctionAttr(funcaddr,FUNCATTR_END)
    begin = start
    while begin < end:
        if GetMnem(begin) == "call":
            AddBpt(begin)
        begin = begin + decode_insn(begin)
    		
def sortfuncbysize(begin, end):
    addr=begin
    addr_map = {}
    while addr < end:
        addrnext = NextFunction(addr)
        addr_map[addr] = addrnext - addr
        addr = addrnext
    arr = sorted(addr_map.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)
    for item in arr:
        print("%x-%x" % (item[0], item[1]))
		
def GetSegRange(segname):
    seg = FirstSeg() 
    while seg != 0xffffffff: 
        if SegName(seg) == segname: 
            break
        seg = NextSeg(seg)
    if seg == 0xffffffff:
        return 0, 0
    return SegStart(seg), SegEnd(seg)       

def AddCFStringRef():
    begin, end = GetSegRange('__cfstring')
    if begin == 0:
        return
    count = (end - begin) / 16
    for i in range(0, count):
        cfstring = begin + i * 16
        cstring = Dword(cfstring + 8)
        AddCodeXref(cfstring, cstring, XREF_USER | fl_F)
		
def SetTypeOnObjCFunc():
	# auto tag Objective-C parameter type
    segb, sege = GetSegRange('__text')
    segb -= 1
    while NextFunction(segb) != BADADDR:
        faddr = NextFunction(segb)
        funcsize = GetFunctionAttr(faddr, FUNCATTR_END) - faddr
        funcname = GetFunctionName(faddr)
        if funcname.find('[') != -1:
            # ObjC func
            if funcname.find(':') != -1:
                # find ObjC func which have params
                params = funcname.split(' ')[1].split(':')
                origintype = GetType(faddr);
                if origintype is not None:
                    origintype= origintype.split(',')
                    origintype[0] = origintype[0].replace('__cdecl','f')
                    if len(origintype) - 2 <= len(params): 
                        for i in range(2, len(origintype)):
                            if i == len(origintype) - 1:
                                origintype[i] = origintype[i].replace(')', '')
                            params[i - 2] = params[i - 2].replace('set', '')
                            origintype[i] += ' ' + params[i - 2].lower()
                            if i == len(origintype) - 1:
                                origintype[i]  += ')'
                        newtype = ','.join(origintype)
                        SetType(faddr, newtype)
                else:
                    print 'sp:%x' % faddr
        segb = faddr + funcsize - 1

		