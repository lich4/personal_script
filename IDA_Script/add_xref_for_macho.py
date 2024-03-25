import idc
import idautils

is64 = True
ptsize = 8 if is64 else 4
get_pt = get_qword if is64 else get_wide_dword
b2s = lambda d: d.decode() if d is not None and type(d) == bytes and str != bytes else d

def addxref(sel, f_ea):
    add_cref(sel, f_ea, XREF_USER | fl_F)
    add_cref(f_ea, sel, XREF_USER | fl_F)

def addobjcref():
    sel_map = {}
    imp_map = {}
    forbit_meth = set([
        ".cxx_construct",
        ".cxx_destruct",
        "alloc",
        "allowsWeakReference",
        "allocWithZone:",
        "autoContentAccessingProxy",
        "autorelease",
        "awakeAfterUsingCoder:",
        "beginContentAccess",
        "class",
        "classForCoder",
        "conformsToProtocol:",
        "copy",
        "copyWithZone:",
        "dealloc",
        "description",
        "debugDescription",
        "discardContentIfPossible",
        "doesNotRecognizeSelector:",
        "encodeWithCoder:",
        "endContentAccess",
        "finalize",
        "forwardingTargetForSelector:",
        "forwardInvocation:",
        "hash",
        "init",
        "initWithCoder:",
        "initialize",
        "instanceMethodForSelector:",
        "instanceMethodSignatureForSelector:",
        "instancesRespondToSelector:",
        "isContentDiscarded",
        "isEqual:",
        "isKindOfClass:",
        "isMemberOfClass:",
        "isProxy",
        "isSubclassOfClass:",
        "load",
        "methodForSelector:",
        "methodSignatureForSelector:",
        "mutableCopy",
        "mutableCopyWithZone:",
        "new",
        "performSelector:",
        "performSelector:withObject:",
        "performSelector:withObject:withObject:",
        "release",
        "replacementObjectForCoder:",
        "resolveClassMethod:",
        "resolveInstanceMethod:",
        "respondsToSelector:",
        "retain",
        "retainCount",
        "retainWeakReference",
        "self",
        "setVersion:",
        "superclass",
        "supportsSecureCoding",
        "version",
        "zone",
    ])
    # find the segment which contains objc method names
    seg = ida_segment.get_segm_by_name("__objc_selrefs")
    if not seg:
        print("cannot find __objc_selrefs")
        return
    for selref_ea in range(seg.start_ea, seg.end_ea, ptsize):
        sel_ea = get_pt(selref_ea)
        sel_name = b2s(get_strlit_contents(sel_ea))
        if sel_name not in forbit_meth:
            sel_map[sel_name] = sel_ea
    # get objc func table
    for addr in idautils.Functions():
        func_name = b2s(get_name(addr))
        if func_name[0] in ['+', '-'] and func_name[1] == '[' and func_name[-1] == ']': # +[? ?] -[? ?]
            sel_name = func_name[2:-1].split(" ")[-1]
            # may be more than one function with same sel but differenct class
            if sel_name not in forbit_meth:
                if sel_name not in imp_map:
                    imp_map[sel_name] = []
                imp_map[sel_name].append(addr)
    # make xref
    for (sel_name, sel_ea) in sel_map.items():
        if sel_name in imp_map:
            for f_addr in imp_map[sel_name]:
                addxref(sel_ea, f_addr)
            print("added xref for " + sel_name)

if __name__ == "__main__":
    addobjcref()

