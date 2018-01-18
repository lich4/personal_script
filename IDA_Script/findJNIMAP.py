def find_seg_by_name(segname):
    ea = FirstSeg()
    while ea != BADADDR:
        if SegName(ea) == segname:
            return ea
        ea = NextSeg(ea)
    return -1

def init_jni_bridge():
    data_seg = find_seg_by_name(".data")
    if data_seg == -1:
        return
    data_begin = SegStart(data_seg)
    data_end = SegEnd(data_seg)
    
    while data_begin < data_end:
        if SegName(Dword(data_begin)) != ".rodata" or SegName(Dword(data_begin)) != ".rodata":
            data_begin = data_begin +12
            continue
        funcname = GetString(Dword(data_begin))
        funcdesc = GetString(Dword(data_begin+4))
        if re.match(ur"^[0-9a-zA-Z_]*$", funcname) is None:
            data_begin = data_begin +12
            continue
        if SegName(Dword(data_begin+8)) == ".text":
            addr_ori = Dword(data_begin+8)
            addr_fix = LocByName(GetFunctionName(addr_ori))
            if addr_ori == addr_fix or addr_ori == addr_fix + 1:
                print funcname
        data_begin = data_begin + 12
        
if __name__ == "__main__":
    init_jni_bridge()
