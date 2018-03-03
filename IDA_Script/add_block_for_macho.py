# this file is for extracting block structure for mach-o file

import idc
import idaapi
import re
import add_block_for_macho as addblk

def add_block_type():
    # it's trouble to add c-style-structure directly into structure table, so we put them into local types instead
    # ----------------------Block_descriptor--------------------------#
    # flag with BLOCK_HAS_COPY_DISPOSE | BLOCK_HAS_SIGNATURE
    enu_Block_Flag = """
        typedef enum _Block_Flag : uint32_t {
            BLOCK_NEEDS_FREE = (1 << 24),
            BLOCK_HAS_COPY_DISPOSE = (1 << 25),
            BLOCK_HAS_CTOR = (1 << 26),
            BLOCK_IS_GC = (1 << 27),
            BLOCK_IS_GLOBAL = (1 << 28),
            BLOCK_USE_STRET = (1 << 29),
            BLOCK_HAS_SIGNATURE = (1 << 30),
            BLOCK_HAS_EXTENDED_LAYOUT = (1 << 31),
        } Block_Flag;
    """

    strudef_Block_descriptor_hcd_hs = "                 \
         typedef struct _Block_descriptor_hcd_hs         \
         {                                               \
             uintptr_t reserved;                         \
             uintptr_t size;                             \
             void (*copy)(void *dst, const void *src);   \
             void (*dispose)(const void *);              \
             const char *signature;                      \
             const char *layout;                         \
         } Block_descriptor_hcd_hs;                      \
     "
    # flag with BLOCK_HAS_COPY_DISPOSE
    strudef_Block_descriptor_hcd = "                    \
         typedef struct _Block_descriptor_hcd            \
         {                                               \
             uintptr_t reserved;                         \
             uintptr_t size;                             \
             void (*copy)(void *dst, const void *src);   \
             void (*dispose)(const void *);              \
         } Block_descriptor_hcd;                         \
     "
    # flag with BLOCK_HAS_SIGNATURE
    strudef_Block_descriptor_hs = "                     \
         typedef struct _Block_descriptor_hs             \
         {                                               \
             uintptr_t reserved;                         \
             uintptr_t size;                             \
             const char *signature;                      \
             const char *layout;                         \
         } Block_descriptor_hs;                          \
     "
    # flag with none of above
    strudef_Block_descriptor_o = "                      \
         typedef struct _Block_descriptor_o              \
         {                                               \
             uintptr_t reserved;                         \
             uintptr_t size;                             \
             const char *signature;                      \
             const char *layout;                         \
         } Block_descriptor_o;                           \
     "
    # origin structure
    strudef_Block_descriptor = "                        \
         typedef struct _Block_descriptor                \
         {                                               \
             uintptr_t reserved;                         \
             uintptr_t size;                             \
         } Block_descriptor;                             \
     "
    # ----------------------Block_layout--------------------------#
    strudef_Block_layout = "                            \
         typedef struct _Block_layout                    \
         {                                               \
             void *isa;                                  \
             int32_t flags;                              \
             int32_t reserved;                           \
             void (*invoke)(void *, ...);                \
             struct Block_descriptor *descriptor;        \
         } Block_layout;                                 \
     "

    # now add two types above
    idc.SetLocalType(-1, "typedef unsigned long uintptr_t;typedef int int32_t;", 0)

    idc.SetLocalType(-1, enu_Block_Flag, 0);
    idc.SetLocalType(-1, strudef_Block_descriptor_hcd_hs, 0)
    idc.SetLocalType(-1, strudef_Block_descriptor_hcd, 0)
    idc.SetLocalType(-1, strudef_Block_descriptor_hs, 0)
    idc.SetLocalType(-1, strudef_Block_descriptor_o, 0)
    idc.SetLocalType(-1, strudef_Block_descriptor, 0)
    idc.SetLocalType(-1, strudef_Block_layout, 0)

    # then add from local type to structures
    idc.SetType(0, "_Block_Flag");
    idc.SetType(0, "_Block_descriptor_hcd_hs")  # address set to 0 just for import from localtypes into structures
    idc.SetType(0, "_Block_descriptor_hcd")
    idc.SetType(0, "_Block_descriptor_hs")
    idc.SetType(0, "_Block_descriptor_o")
    idc.SetType(0, "_Block_descriptor")
    idc.SetType(0, "_Block_layout")

    global offset_flags, offset_invoke, offset_descri
    tmpid = idc.GetStrucIdByName("_Block_layout")
    offset_flags = idc.GetMemberOffset(tmpid, "flags")
    offset_invoke = idc.GetMemberOffset(tmpid, "invoke")
    offset_descri = idc.GetMemberOffset(tmpid, "descriptor")

    if tmpid == -1 or offset_flags == -1 or offset_invoke == -1 or offset_descri == -1:
        raise ValueError, "struct define error tmpid=%x oflags=%x oinvoke=%x odecri=%x!" % (tmpid, offset_flags, offset_invoke, offset_descri)

def imp_cb(ea, name, ord):
    global globalblock_addr, stackblock_addr
    if name.find("NSConcreteGlobalBlock") != -1:
        globalblock_addr = ea
    elif name.find("NSConcreteStackBlock") != -1:
        stackblock_addr = ea
        # sometimes __NSConcreteStackBlock_ptr is referenced, and not __NSConcreteStackBlock itself
        f = idc.DfirstB(stackblock_addr)
        if idc.SegName(f) == '__got':
            stackblock_addr = f

    return True


def find_xref(addr, xrefs, restriarea):
    ref = idc.DfirstB(addr)
    while ref != BADADDR:
        if idc.SegName(ref) in restriarea:
            xrefs.append(ref)
        ref = idc.DnextB(addr, ref)


def get_block_call():
    # we tranverse import table and finally get two functions, which exists in libSystem.B.dylib
    global globalblock_set, stackblock_set
    nimps = idaapi.get_import_module_qty()
    for i in xrange(0, nimps):
        name = idaapi.get_import_module_name(i)
        if name.find("libSystem.B.dylib") != -1:
            idaapi.enum_import_names(i, imp_cb)
            break
    # then we find all xref to these two functions
    if globalblock_addr != 0:
        find_xref(globalblock_addr, globalblock_set, ["__const"])
    if stackblock_addr != 0:
        find_xref(stackblock_addr, stackblock_set, ["__text"])


def get_proto_for_sign(sign):
    typemap = {'B': "bool", 'c': "bool", 'C': "unsigned char", 'd': "double", 'f': "float", 'i': "int",
               'I': "unsigned int", 'l': "long", 'L': "long", 'q': "long long", 'Q': "unsigned long long",
               's': "short", 'S': "unsigned short", 'v': "void"}
    sl = len(sign)
    descriarr = []
    while True:
        match = re.search(r'(?P<type>[^0-9]+)(?P<size>[0-9]+)', sign)
        if match == None:
            break
        tmp1 = match.group("type")
        tmp2 = match.group(0)
        tmp3 = match.group("size")
        descriarr.append({"type": tmp1, "off": int(tmp3)})
        sign = sign[len(tmp2):]

    for item in descriarr:
        ch = item["type"][0]
        ct = item["type"]
        if ch in typemap:
            if len(ct) != 1:
                print "unknown type:", ct
            item["type"] = typemap[ch]
        elif ch == '{':  # format as {MyClass=...
            match = re.search(r'{([^=]+)=', ct)
            if match == None:
                print "unknown type:", ct
            item["type"] = match.group(1)
        elif ch == '@':
            if ct == "@" or ct == "@?":
                item["type"] = "id"
            elif ct[1] == '"':
                match = re.search(r'([0-9a-zA-Z_]+)', ct)
                if match == None:
                    print "unknown type:", ct
                item["type"] = match.group(1) + "*"
                # detect if class defined
                objtype = match.group(1)
                print "init type:", objtype
                idc.SetType(0, objtype)
                if BADADDR == GetStrucIdByName(objtype):
                    # we define a temporary type
                    SetLocalType(-1, "typedef struct " + objtype + " {void* isa;} _" + objtype + ";", 0)
            else:
                print "unknown type:", ct
                item["type"] = "id"
        elif ch == '^':
            if len(ct) != 2 or ct[1] not in typemap:
                print "unknown type:", ct
                item["type"] = "void*"
            else:
                item["type"] = typemap[ct[1]]
    resulttype = descriarr[0]["type"]
    resulttype = resulttype + " func("
    if len(descriarr) > 1:
        for i in range(1, len(descriarr) - 1):
            resulttype = resulttype + descriarr[i]["type"] + ","
        resulttype = resulttype[0: len(resulttype) - 1]
    resulttype = resulttype + ");"
    return resulttype


def extract_description(addr, flag, funcaddr, descriaddr):
    prototype = "void func(void);"

    blktyp = "_Block_descriptor"

    if (flag & BLOCK_HAS_COPY_DISPOSE):
        blktyp = blktyp + "_hcd"

    if (flag & BLOCK_HAS_SIGNATURE):
        blktyp = blktyp + "_hs"

    if blktyp == "_Block_descriptor":
        blktyp = "_Block_descriptor_o"

    tmpid = idc.GetStrucIdByName(blktyp)

    idc.MakeNameEx(descriaddr, "block_descriptor_%x" % addr, idc.SN_NOWARN)
    idc.SetType(descriaddr, blktyp)

    # print "extract_description(addr=%x, flag=%x, funcaddr=%x, descriaddr=%x)" % (addr, flag, funcaddr, descriaddr)
    # print "blktyp: %s" % blktyp

    if (flag & BLOCK_HAS_COPY_DISPOSE):
        offset_copy = idc.GetMemberOffset(tmpid, "copy")
        offset_dispose = idc.GetMemberOffset(tmpid, "dispose")

        if is64bit:
            copyaddr = idc.Qword(descriaddr + offset_copy)
            disposeaddr = idc.Qword(descriaddr + offset_dispose)
        else:
            copyaddr = idc.Dword(descriaddr + offset_copy)
            disposeaddr = idc.Dword(descriaddr + offset_dispose)
        
        if isarm: # and not is64bit?
            # fixup thumb/arm
            copyaddr &= 0xFFFFFFFFFFFFFFFE
            disposeaddr &= 0xFFFFFFFFFFFFFFFE

        if copyaddr != 0:
            idc.MakeName(copyaddr, "block_copy_%x" % addr)
            idc.SetType(copyaddr, "void copy(void *dst, const void *src);")

        if disposeaddr != 0:
            idc.MakeName(disposeaddr, "block_dispose_%x" % addr)
            idc.SetType(disposeaddr, "void dispose(const void *);")
        
    
    if (flag & BLOCK_HAS_SIGNATURE):
        offset_sign = idc.GetMemberOffset(tmpid, "signature")
        offset_layout = idc.GetMemberOffset(tmpid, "layout")

        if is64bit:
            signptr = idc.Qword(descriaddr + offset_sign)
            layoutptr = idc.Qword(descriaddr + offset_layout)
        else:
            signptr = idc.Dword(descriaddr + offset_sign)
            layoutptr = idc.Dword(descriaddr + offset_layout)
        if signptr != 0:
            # print "sign at 0x%x" % signptr
            prototype = get_proto_for_sign(idc.GetString(signptr))
        if layoutptr != 0:
            print "Unhandled layoutptr %x" % layoutptr
            pass


    # # if funcaddr > 0:
    #     idc.MakeName(funcaddr, "block_invoke_%x" % addr)
    #     idc.SetType(funcaddr, prototype)

    return prototype


def extract_globalblock(addr):
    # this kind of block targetted to absolute address
    print "------%x------" % addr
    global offset_invoke, offset_flags, offset_descri
    idc.MakeName(addr, "global_block_%x" % addr)
    idc.SetType(addr, "_Block_layout")
    flag = idc.Dword(addr + offset_flags)
    if is64bit:
        funcaddr = idc.Qword(addr + offset_invoke)
        descriaddr = idc.Qword(addr + offset_descri)
    else:
        funcaddr = idc.Dword(addr + offset_invoke)
        descriaddr = idc.Dword(addr + offset_descri)
    if isarm:
        funcaddr &= 0xFFFFFFFFFFFFFFFE

    prototype = extract_description(addr, flag, funcaddr, descriaddr) 

    if funcaddr != 0:
        idc.MakeName(funcaddr, "global_block_invoke_%x" % addr)
        idc.SetType(funcaddr, prototype)


def extract_stackblock(addr, bptreg=None):
    # this kind of block targetted to stack address space
    print "------%x------" % addr
    # find the stack frame for this function
    # which register store the base of current block structure
    
    if bptreg is None:
        bptreg = idc.GetOpnd(addr, 0)

    # print "bptreg is %s" % bptreg

    # find base stored position of current block in stack
    # on arm it'd be "STR R1, [SP,#0x48+var_30]"
    # on x86 it'd be "lea rbx, [rbp+var_30]; mov rbx, rX"
    # OR mov [rbp+var_58], rX !
    # so we need prev instruction on x86

    begin = addr
    count = 0

    for count in xrange(0, 20):
        begin += idaapi.decode_insn(begin)
        if idc.GetOpnd(begin, 0) == bptreg or idc.GetOpnd(begin, 1) == bptreg:
            # print "Found bptreg reference at %x: %s" % (begin, idc.GetDisasm(begin))
            break

    if count == 20 - 1:
        return "Failed to find bptreg reference"

    match = re.search(r'(var_|block_)[0-9A-Fa-f]+', idc.GetDisasm(begin))
    if match is None:
        print "Cant detect varname in %s, trying just next instruction" % idc.GetDisasm(begin)
        begin += idaapi.decode_insn(begin)
        match = re.search(r'(var_|block_)[0-9A-Fa-f]+', idc.GetDisasm(begin))

    if match is None:
        return "unhandled %x -- cant detect varname at %x" % (addr, begin)

    varname = match.group(0)
    frameid = idc.GetFrame(addr)
    varoff = idc.GetMemberOffset(frameid, varname)
    
    if varoff == -1:
        return "unhandled %x -- cant find varoff in frame" % addr
    # first delete those members which occupy block space
    new_name = "block_%x" % addr
    id_Block_layout = idc.GetStrucIdByName("_Block_layout")
    size_Block_layout = idc.GetStrucSize(id_Block_layout)
    beginoff = varoff
    endoff = varoff + size_Block_layout
    for iaddr in range(beginoff, endoff):
        idc.DelStrucMember(frameid, iaddr)
    if 0 != idc.AddStrucMember(frameid, new_name, varoff, idc.FF_STRU | idc.FF_DATA, id_Block_layout, size_Block_layout):
        return "unhandled %x -- cant add struc member" % addr
    
    # get structure member data from decompiled source
    funcaddr = 0
    descriaddr = 0
    flag = 0
    lines = str(idaapi.decompile(addr)).split('\n')

    NSConcreteStackBlock_occur_cnt = 0

    for line in lines:
        line = line.lower()
        if '_NSConcreteStackBlock'.lower() in line:
            NSConcreteStackBlock_occur_cnt += 1

        if line.find(new_name) != -1:
            if line.find(".flags") != -1:
                if flag == 0:
                    match = re.search(r'flags = (.*);', line)
                    try:
                        flag_str = match.group(1).strip()
                        # print "flag_str: %s" % flag_str
                        flag = int(flag_str, 16 if flag_str[:2] == '0x' else 10) & 0xffffffff  # format as -1073741824
                    except:
                        flag = 0
            elif line.find(".invoke") != -1:
                if funcaddr == 0:
                    match = re.search(r'invoke = (\(.*\))?([0-9a-zA-Z_]+);', line)
                    try:
                        funcaddr = idc.LocByName(match.group(2))
                        if isarm:
                            funcaddr &= 0xfffffffffffffffe
                    except:
                        funcaddr = 0
            elif line.find(".descriptor") != -1:
                if descriaddr == 0:
                    match = re.search(r'descriptor = (\(.*\))?&?([0-9a-zA-Z_]+);', line)
                    try:
                        descriaddr = idc.LocByName(match.group(2))
                    except:
                        descriaddr = 0

    if flag == 0 or descriaddr == 0:
        ret = "unhandled %x -- flag %x descriaddr %x" % (addr, flag, descriaddr)
        if NSConcreteStackBlock_occur_cnt > 1:
            ret = ret + "\nfound %x stack blocks near %x but only first one was processed" % (NSConcreteStackBlock_occur_cnt, addr)
        return ret


    prototype = extract_description(addr, flag, funcaddr, descriaddr)

    if funcaddr != 0:
        idc.MakeName(funcaddr, "stack_block_invoke_%x" % addr)
        idc.SetType(funcaddr, prototype)

    if NSConcreteStackBlock_occur_cnt > 1:
        return "found %x stack blocks near %x but only first one was processed" % (NSConcreteStackBlock_occur_cnt, addr)

    return None

# constants
BLOCK_HAS_COPY_DISPOSE = 1 << 25
BLOCK_HAS_SIGNATURE = 1 << 30

# variables
globalblock_addr = 0
stackblock_addr = 0
globalblock_set = []
stackblock_set = []
is64bit = False
isarm   = False
offset_flags = -1
offset_invoke = -1
offset_descri = -1

if __name__ == "__main__":
    print "--------------init--------------"

    if (idc.GetCharPrm(INF_LFLAGS) & LFLG_64BIT) != 0:
        is64bit = True

    isarm = 'ax' not in idaapi.ph_get_regnames()

    add_block_type()
    get_block_call()

    print "--------------extract_globalblock--------------"
    for i in globalblock_set:
        extract_globalblock(i)

    all_errs = []

    print "--------------extract_stackblock--------------"
    for i in stackblock_set:
        ret = extract_stackblock(i)
        if ret is not None:
            all_errs.append((i, ret))
            print ret
            idc.Warning(ret)

    print "Done! %d errors: " % len(all_errs)
    for addr, err in all_errs:
        print "%x: %s" % (addr, err)
