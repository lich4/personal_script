import idc

def addxref(x, y, z):
    """
    add reference for objc_meth_addr <=> objc_methname_addr <=> msgsend_call_addr
    :param x: msgsend_call_addr
    :param y: objc_meth_addr
    :param z: objc_methname_addr
    :return: nothing
    """
    AddCodeXref(x, y, XREF_USER | fl_F)
#    AddCodeXref(y, x, XREF_USER | fl_F)
#    AddCodeXref(x, z, XREF_USER | fl_F)
#    AddCodeXref(z, x, XREF_USER | fl_F)
    AddCodeXref(y, z, XREF_USER | fl_F)
#    AddCodeXref(z, y, XREF_USER | fl_F)


def addobjcref():
    """
    add reference for math-o file
    :return: nothing
    """
    objc_meth_map = {}
    methnamebegin = 0
    methnameend = 0
    forbitmeth = [
        "alloc",
        "allocWithZone:",
        "allowsWeakReference",
        "autorelease",
        "class",
        "conformsToProtocol:",
        "copy",
        "copyWithZone:",
        "dealloc",
        "debugDescription",
        "description",
        "doesNotRecognizeSelector:",
        "finalize",
        "forwardingTargetForSelector:",
        "forwardInvocation:",
        "hash",
        "init",
        "initialize",
        "instanceMethodForSelector:"
        "instanceMethodSignatureForSelector:",
        "instancesRespondToSelector:",
        "isEqual",
        "isKindOfClass:",
        "isMemberOfClass:",
        "isProxy",
        "isSubclassOfClass:",
        "load",
        "methodForSelector:",
        "methodSignatureForSelector:",
        "mutableCopy",
        "mutableCopyWithZone:",
        "performSelector:",
        "performSelector:withObject:",
        "performSelector:withObject:withObject:",
        "respondsToSelector:",
        "release",
        "resolveClassMethod:",
        "resolveInstanceMethod:",
        "retain",
        "retainCount",
        "retainWeakReference",
        "superclass",
        "zone",
        ".cxx_construct",
        ".cxx_destruct",
    ]
    # find the segment which contains objc method names
    curseg = FirstSeg()
    while curseg != 0xffffffff:
        if "__objc_methname" == SegName(curseg):
            methnamebegin = SegStart(curseg)
            methnameend = SegEnd(curseg)
            break
        curseg = NextSeg(curseg)
    # get objc method names
    if methnamebegin != 0:
        while methnamebegin < methnameend:
            funcname = GetString(methnamebegin)
            objc_meth_map[funcname] = methnamebegin
            methnamebegin = methnamebegin + len(funcname) + 1
    # get objc func table
    funcmap = {}
    addr = PrevFunction(-1)
    while addr != 0xffffffff:
        curname = GetFunctionName(addr)
        if -1 != curname.find('['):
            curname = curname.replace("[", "").replace("]", "")
            curname = curname.split(" ")[1]
            # may be more than one function with same sel but differenct class
            if curname not in funcmap:
                funcmap[curname] = []
            funcmap[curname].append(addr)
        addr = PrevFunction(addr)
    # make xref
    for (k, v) in objc_meth_map.items():
        # find corresponding func addr
        if k in funcmap and k not in forbitmeth:
            farr = funcmap[k]
            # find xref to code and make xref for each
            curref = DfirstB(v)
            while curref != 0xffffffff:
                for f in farr:
                    addxref(curref, f, v)
                curref = DnextB(v, curref)
            print "added xref for " + k

if __name__ == "__main__":
    addobjcref()