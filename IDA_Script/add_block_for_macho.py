# this file is for extracting block structure for mach-o file

import idc
import idaapi
import re


def add_block_type():
    # it's trouble to add c-style-structure directly into structure table, so we put them into local types instead
    # ----------------------Block_descriptor--------------------------#
    # flag with BLOCK_HAS_COPY_DISPOSE | BLOCK_HAS_SIGNATURE
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
             volatile int32_t flags;                     \
             int32_t reserved;                           \
             void (*invoke)(void *, ...);                \
             struct Block_descriptor *descriptor;        \
         } Block_layout;                                 \
     "

    # now add two types above
    SetLocalType(-1, "typedef unsigned long uintptr_t;typedef int int32_t;", 0)
    SetLocalType(-1, strudef_Block_descriptor_hcd_hs, 0)
    SetLocalType(-1, strudef_Block_descriptor_hcd, 0)
    SetLocalType(-1, strudef_Block_descriptor_hs, 0)
    SetLocalType(-1, strudef_Block_descriptor_o, 0)
    SetLocalType(-1, strudef_Block_descriptor, 0)
    SetLocalType(-1, strudef_Block_layout, 0)

    # then add from local type to structures
    SetType(0, "_Block_descriptor_hcd_hs")  # address set to 0 just for import from localtypes into structures
    SetType(0, "_Block_descriptor_hcd")
    SetType(0, "_Block_descriptor_hs")
    SetType(0, "_Block_descriptor_o")
    SetType(0, "_Block_descriptor")
    SetType(0, "_Block_layout")

    global offset_flags, offset_invoke, offset_descri
    tmpid = GetStrucIdByName("_Block_layout")
    offset_flags = GetMemberOffset(tmpid, "flags")
    offset_invoke = GetMemberOffset(tmpid, "invoke")
    offset_descri = GetMemberOffset(tmpid, "descriptor")
    if tmpid == -1 or offset_flags == -1 or offset_invoke == -1 or offset_descri == -1:
        raise ValueError, "struct define error!"


def imp_cb(ea, name, ord):
    global globalblock_addr, stackblock_addr
    if name.find("NSConcreteGlobalBlock") != -1:
        globalblock_addr = ea
    elif name.find("NSConcreteStackBlock") != -1:
        stackblock_addr = ea
    return True


def find_xref(addr, xrefs, restriarea):
    ref = DfirstB(addr)
    while ref != BADADDR:
        if SegName(ref) in restriarea:
            xrefs.append(ref)
        ref = DnextB(addr, ref)


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
                SetType(0, objtype)
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
    offset_copy = -1
    offset_dispose = -1
    offset_sign = -1
    offset_layout = -1
    if (flag & BLOCK_HAS_COPY_DISPOSE) != 0 and (flag & BLOCK_HAS_SIGNATURE) != 0:
        MakeName(descriaddr, "block_descriptor_%x" % addr)
        SetType(descriaddr, "_Block_descriptor_hcd_hs")
        tmpid = GetStrucIdByName("_Block_descriptor_hcd_hs")
        offset_copy = GetMemberOffset(tmpid, "copy")
        offset_dispose = GetMemberOffset(tmpid, "dispose")
        offset_sign = GetMemberOffset(tmpid, "signature")
        offset_layout = GetMemberOffset(tmpid, "layout")
        if is64bit:
            copyaddr = Qword(descriaddr + offset_copy) & 0xFFFFFFFFFFFFFFFE  # fixup thumb/arm
            disposeaddr = Qword(descriaddr + offset_dispose) & 0xFFFFFFFFFFFFFFFE
            signptr = Qword(descriaddr + offset_sign)
            layoutptr = Qword(descriaddr + offset_layout)
        else:
            copyaddr = Dword(descriaddr + offset_copy) & 0xFFFFFFFE
            disposeaddr = Dword(descriaddr + offset_dispose) & 0xFFFFFFFE
            signptr = Dword(descriaddr + offset_sign)
            layoutptr = Dword(descriaddr + offset_layout)
        if signptr != 0:
            prototype = get_proto_for_sign(GetString(signptr))
        if layoutptr != 0:
            pass
        if copyaddr != 0:
            MakeName(copyaddr, "block_copy_%x" % addr)
            SetType(copyaddr, "void copy(void *dst, const void *src);")
        if disposeaddr != 0:
            MakeName(disposeaddr, "block_dispose_%x" % addr)
            SetType(disposeaddr, "void dispose(const void *);")
        if funcaddr > 0:
            MakeName(funcaddr, "block_invoke_%x" % addr)
            SetType(funcaddr, prototype)
    elif (flag & BLOCK_HAS_COPY_DISPOSE) != 0:
        MakeName(descriaddr, "block_descriptor_%x" % addr)
        SetType(descriaddr, "_Block_descriptor_hcd")
        tmpid = GetStrucIdByName("_Block_descriptor_hcd")
        offset_copy = GetMemberOffset(tmpid, "copy")
        offset_dispose = GetMemberOffset(tmpid, "dispose")
        if is64bit:
            copyaddr = Qword(descriaddr + offset_copy) & 0xFFFFFFFFFFFFFFFE  # fixup thumb/arm
            disposeaddr = Qword(descriaddr + offset_dispose) & 0xFFFFFFFFFFFFFFFE
        else:
            copyaddr = Dword(descriaddr + offset_copy) & 0xFFFFFFFE
            disposeaddr = Dword(descriaddr + offset_dispose) & 0xFFFFFFFE
        # print "addr=%x copy=%x dispose=%x" % (addr, copyaddr, disposeaddr)
        if copyaddr != 0:
            MakeName(copyaddr, "block_copy_%x" % addr)
            SetType(copyaddr, "void copy(void *dst, const void *src);")
        if disposeaddr != 0:
            MakeName(disposeaddr, "block_dispose_%x" % addr)
            SetType(disposeaddr, "void dispose(const void *);")
        if funcaddr > 0:
            MakeName(funcaddr, "block_invoke_%x" % addr)
            SetType(funcaddr, prototype)
    elif (flag & BLOCK_HAS_SIGNATURE) != 0:
        MakeName(descriaddr, "block_descriptor_%x" % addr)
        SetType(descriaddr, "_Block_descriptor_hs")
        tmpid = GetStrucIdByName("_Block_descriptor_hs")
        offset_sign = GetMemberOffset(tmpid, "signature")
        offset_layout = GetMemberOffset(tmpid, "layout")
        if is64bit:
            signptr = Qword(descriaddr + offset_sign)
            layoutptr = Qword(descriaddr + offset_layout)
        else:
            signptr = Dword(descriaddr + offset_sign)
            layoutptr = Dword(descriaddr + offset_layout)
        if signptr != 0:
            prototype = get_proto_for_sign(GetString(signptr))
        if layoutptr != 0:
            pass
        # print "addr=%x signptr=%s layoutptr=%x" % (addr, prototype, layoutptr)
        if funcaddr > 0:
            MakeName(funcaddr, "block_invoke_%x" % addr)
            SetType(funcaddr, prototype)
    else:
        MakeName(descriaddr, "block_descriptor_%x" % addr)
        SetType(descriaddr, "_Block_descriptor_o")
        tmpid = GetStrucIdByName("_Block_descriptor_o")
        # print "addr=%x" % addr
    return prototype


def extract_globalblock(addr):
    # this kind of block targetted to absolute address
    print "------%x------" % addr
    global offset_invoke, offset_flags, offset_descri
    MakeName(addr, "global_block_%x" % addr)
    SetType(addr, "_Block_layout")
    flag = Dword(addr + offset_flags)
    if is64bit:
        funcaddr = Qword(addr + offset_invoke) & 0xFFFFFFFFFFFFFFFE  # skip thumb or arm
        descriaddr = Qword(addr + offset_descri)
    else:
        funcaddr = Dword(addr + offset_invoke) & 0xFFFFFFFE
        descriaddr = Dword(addr + offset_descri)
    prototype = "void func(void);"
    if descriaddr != 0:
        prototype = extract_description(addr, flag, funcaddr, descriaddr)
    if funcaddr != 0:
        MakeName(funcaddr, "global_block_invoke_%x" % addr)
        SetType(funcaddr, prototype)


def extract_stackblock(addr):
    # this kind of block targetted to stack address space
    print "------%x------" % addr
    # find the stack frame for this function
    # which register store the base of current block structure
    disasm = GetDisasm(addr)
    bptreg = GetOpnd(addr, 0)
    # find base stored position of current block in stack
    begin = addr
    for count in range(0, 20):
        begin = begin + idaapi.decode_insn(begin)
        if GetOpnd(begin, 0) == bptreg or GetOpnd(begin, 1) == bptreg:
            break
    # match  "STR R1, [SP,#0x48+var_30]"
    match = re.search(r'var_[0-9A-Fa-f]+', GetDisasm(begin))
    if match == None:  # too complex to handle
        print "unhandled %x" % addr
        return
    varname = match.group(0)
    frameid = GetFrame(addr)
    varoff = GetMemberOffset(frameid, varname)
    if varoff == -1:
        print "unhandled %x" % addr
        return
    # first delete those members which occupy block space
    new_name = "block_%x" % addr
    id_Block_layout = GetStrucIdByName("_Block_layout")
    size_Block_layout = GetStrucSize(id_Block_layout)
    beginoff = varoff
    endoff = varoff + size_Block_layout
    for iaddr in range(beginoff, endoff):
        DelStrucMember(frameid, iaddr)
    if 0 != AddStrucMember(frameid, new_name, varoff, FF_STRU | FF_DATA, id_Block_layout, size_Block_layout):
        print "unhandled %x" % addr
        return
        # get structure member data from decompiled source
    funcaddr = 0
    descriaddr = 0
    flag = 0
    lines = idaapi.decompile(addr).__str__().split('\n')
    for line in lines:
        line = line.lower()
        if line.find(new_name) != -1:
            if line.find(".flags") != -1:
                if flag == 0:
                    match = re.search(r'flags = (.*);', line)
                    try:
                        flag = int(match.group(1)) & 0xffffffff  # format as -1073741824
                    except:
                        flag = 0
            elif line.find(".invoke") != -1:
                if funcaddr == 0:
                    match = re.search(r'invoke = .*_([0-9a-f]+);', line)
                    try:
                        funcaddr = int(match.group(1), 16) & 0xfffffffffffffffe  # fix thumb/arm
                    except:
                        funcaddr = 0
            elif line.find(".descriptor") != -1:
                if descriaddr == 0:
                    match = re.search(r'descriptor = .*_([0-9a-f]+);', line)
                    try:
                        descriaddr = int(match.group(1), 16)
                    except:
                        descriaddr = 0
    if flag == 0 or descriaddr == 0:
        print "unhandled %x" % addr
        return
    prototype = "void func(void);"
    if descriaddr != 0:
        prototype = extract_description(addr, flag, funcaddr, descriaddr)
    if funcaddr != 0:
        MakeName(funcaddr, "stack_block_invoke_%x" % addr)
        SetType(funcaddr, prototype)


# constants
BLOCK_DEALLOCATING = 0x0001
BLOCK_REFCOUNT_MASK = 0xfffe
BLOCK_NEEDS_FREE = 1 << 24
BLOCK_HAS_COPY_DISPOSE = 1 << 25
BLOCK_HAS_CTOR = 1 << 26
BLOCK_IS_GC = 1 << 27
BLOCK_IS_GLOBAL = 1 << 28
BLOCK_USE_STRET = 1 << 29  # undefined if !BLOCK_HAS_SIGNATURE
BLOCK_HAS_SIGNATURE = 1 << 30
BLOCK_HAS_EXTENDED_LAYOUT = 1 << 31

# variables
globalblock_addr = 0
stackblock_addr = 0
globalblock_set = []
stackblock_set = []
is64bit = False
offset_flags = -1
offset_invoke = -1
offset_descri = -1

if __name__ == "__main__":
    print "--------------init--------------"
    if (GetCharPrm(INF_LFLAGS) & LFLG_64BIT) != 0:
        is64bit = True
    add_block_type()
    get_block_call()

    print "--------------extract_globalblock--------------"
    for i in globalblock_set:
        extract_globalblock(i)

    print "--------------extract_stackblock--------------"
    for i in stackblock_set:
        extract_stackblock(i)
