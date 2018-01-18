# -*- coding: utf-8 -*-

# 该版本增加右键菜单，而不需要对整个二进制增加xref，只在用户选择的函数上分析函数调用，适合大文件分析

import ida_hexrays
import ida_kernwin
import idc
import os
import sqlite3

ACTION_NAME = "find:objectivec_func_caller"
ACTION_SHORTCUT = "Ctrl+Shift+F"

def analyze(cu):
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
    curseg = idc.FirstSeg()
    while curseg != 0xffffffff:
        if "__objc_methname" == idc.SegName(curseg):
            methnamebegin = idc.SegStart(curseg)
            methnameend = idc.SegEnd(curseg)
            break
        curseg = idc.NextSeg(curseg)
    # get objc method names
    if methnamebegin != 0:
        while methnamebegin < methnameend:
            funcname = idc.GetString(methnamebegin)
            objc_meth_map[funcname] = methnamebegin
            methnamebegin = methnamebegin + len(funcname) + 1
    # get objc func table
    funcmap = {}
    addr = idc.PrevFunction(-1)
    while addr != 0xffffffff:
        curname = idc.GetFunctionName(addr)
        if -1 != curname.find('['):
            curname = curname.replace("[", "").replace("]", "")
            curname = curname.split(" ")[1]
            # may be more than one function with same sel but differenct class
            if curname not in funcmap:
                funcmap[curname] = []
            funcmap[curname].append(addr)
        addr = idc.PrevFunction(addr)
    # make xref
    result = []
    indx = 0
    for (k, v) in objc_meth_map.items():
        # find corresponding func addr
        if k in funcmap and k not in forbitmeth:
            farr = funcmap[k]
            # find xref to code and make xref for each
            curref = idc.DfirstB(v)
            while curref != 0xffffffff:
                for f in farr:
                    cu.execute('insert into xref values (?,?,?,?,?)', [indx, curref, f, v, k])
                    indx += 1
                curref = idc.DnextB(v, curref)
    return result


def addxref(x, y, z, i, k):
    idc.AddCodeXref(x, y, idc.XREF_USER | idc.fl_F)
    idc.AddCodeXref(y, z, idc.XREF_USER | idc.fl_F)
    print 'add xref for', k

class get_caller(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.dbfilename = idc.get_root_filename() + '.xref'

        if not os.path.exists(self.dbfilename):
            print 'create db'
            self.cx = sqlite3.connect(self.dbfilename)
            self.cu = self.cx.cursor()
            self.cu.execute('create table xref (i integer primary key, x integer, y integer, z integer, k text)')
            analyze(self.cu)
            self.cx.commit()
            self.cu.execute('select count (*) from xref')
            count, = self.cu.fetchone()
            print 'Analyse %d xrefs ok' % (count)
        else:
            print 'find db'
            self.cx = sqlite3.connect(self.dbfilename)
            self.cu = self.cx.cursor()
            print 'loaded db'

    def activate(self, ctx):
        # Get current function address
        print 'activate'
        curfunc = idc.get_func_attr(idc.get_screen_ea(), idc.FUNCATTR_START)
        self.cu.execute('select * from xref where y == %d' % curfunc)
        print 'find calls'
        while True:
            r = self.cu.fetchone()
            if r is None:
                break
            i, x, y, z, k = r
            addxref(x, y, z, i, k)
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        vu.refresh_view(True)
        return 1

    def update(self, ctx):
        print 'update'
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET

class my_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME)
my_hooks = my_hooks_t()
my_hooks.hook()

if ida_hexrays.init_hexrays_plugin():
    ida_kernwin.register_action(ida_kernwin.action_desc_t(ACTION_NAME, 'find:objectivec_func_caller',
                get_caller(), ACTION_SHORTCUT))
else:
    print 'hexrays is not available.'