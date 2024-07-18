#!python

import argparse
import os
import sys
import tempfile
import lief
from lief.MachO import *

ver = "v1.0"

EMPTY_ENT = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
</dict>
</plist>
"""

dylib_keymap = {
    LoadCommand.TYPE.ID_DYLIB:           "id", 
    LoadCommand.TYPE.LOAD_DYLIB:         "load", 
    LoadCommand.TYPE.REEXPORT_DYLIB:     "reexport", 
    LoadCommand.TYPE.LOAD_WEAK_DYLIB:    "weak", 
    LoadCommand.TYPE.LAZY_LOAD_DYLIB:    "lazy", 
    LoadCommand.TYPE.LOAD_UPWARD_DYLIB:  "upwardoad", 
    LoadCommand.TYPE.PREBOUND_DYLIB:     "prebound",
}

dylib_ctor_map = {
    "id":       DylibCommand.id_dylib,
    "load":     DylibCommand.load_dylib,
    "reexport": DylibCommand.reexport_dylib,
    "weak":     DylibCommand.weak_lib,
    "lazy":     DylibCommand.lazy_load_dylib,
    "upwardoad":DylibCommand.load_upward_dylib,
}

version2str = lambda version: ".".join([str(i) for i in version])
version2int = lambda version: (version[2]) | (version[1] << 8) | (version[0] << 16)

def get_arch(cpu_type, cpu_subtype):
    cpu_keymap = {
        Header.CPU_TYPE.ARM: "arm",
        Header.CPU_TYPE.ARM64: "arm64",
        Header.CPU_TYPE.X86: "x86",
        Header.CPU_TYPE.X86_64: "x86_64",
    }
    if cpu_type not in cpu_keymap:
        return "unknown"
    s = cpu_keymap[cpu_type]
    if cpu_type == Header.CPU_TYPE.ARM64 and cpu_subtype > 0:
        s += "e abi=" + hex(cpu_subtype)
    return s

class MachOFile:
    def __init__(self, path):
        self.path = path
        self.valid = lief.is_macho(path)
        if self.valid:
            self.obj = parse(path, config=ParserConfig.quick)
            if is_fat(path):
                self.fatnum = len(self.obj)
            else:
                self.fatnum = 0

    def write(self, path=""):
        if not path:
            path = self.path
        self.obj.write(path)
        if self.fatnum == 1: # lief will generate nonfat file, so fix it
            os.system("lipo -create -output {} {}".format(path, path))
        return True

def add_dylib(args, obj=None):
    need_update = False
    if obj:
        name = args.loadpath
        ctor = dylib_ctor_map[args.command]
        command = ctor(name)
        if args.index != -1:
            obj.add(command, args.index)
        else:
            obj.add(command)
        print("Successfully insert {}".format(name))
        return True
    target = args.target
    if not os.path.exists(target):
        print("target file not exist")
        return
    name = os.path.basename(target)
    f = MachOFile(target)
    if not f.valid:
        print("macho invalid")
        return
    for obj in f.obj:
        header = obj.header
        print("{} (architecture {})".format(name, get_arch(header.cpu_type, header.cpu_subtype)))
        if add_dylib(args, obj):
            need_update = True
    if need_update:
        path = args.output if args.output else args.target
        print("Successfully write to " + path)
        f.write(path)

def chg_dylib(args, obj=None):
    need_update = False
    if obj:
        index_max = len(obj.commands)
        to_del_index = None
        new_cmd = None
        for index, cmd in enumerate(obj.commands):
            if cmd.command in dylib_keymap:
                dylib_type = dylib_keymap[cmd.command]
                if args.command and args.command != dylib_type:
                    continue
                if cmd.name != args.loadpath:
                    continue
                to_del_index = index
                ctor = dylib_ctor_map[dylib_type]
                new_cmd = ctor(args.chg_dylib, cmd.timestamp, version2int(cmd.current_version), version2int(cmd.compatibility_version))
                need_update = True
                break
        if to_del_index:
            obj.remove_command(to_del_index)
            obj.add(new_cmd, to_del_index)
            print("Successfully update [{}/{}] {} -> {}".format(index, index_max, args.loadpath, args.chg_dylib))
        return need_update
    target = args.target
    if not os.path.exists(target):
        print("target file not exist")
        return
    name = os.path.basename(target)
    f = MachOFile(target)
    if not f.valid:
        print("macho invalid")
        return
    for obj in f.obj:
        header = obj.header
        print("{} (architecture {})".format(name, get_arch(header.cpu_type, header.cpu_subtype)))
        if chg_dylib(args, obj):
            need_update = True
    if need_update:
        path = args.output if args.output else args.target
        print("Successfully write to " + path)
        f.write(path)

def del_dylib(args, obj=None):
    need_update = False
    if obj:
        index_max = len(obj.commands)
        to_del_lst = list()
        for index, cmd in enumerate(obj.commands):
            if cmd.command in dylib_keymap:
                dylib_type = dylib_keymap[cmd.command]
                if args.command and args.command != dylib_type:
                    continue
                if cmd.name != args.loadpath:
                    continue
                to_del_lst.append({
                    "index": index,
                    "name": cmd.name,
                })
        for item in to_del_lst:
            obj.remove_command(item["index"])
            print("Successfully remove [{}/{}] {}".format(item["index"], index_max, item["name"]))
            need_update = True
        return need_update
    target = args.target
    if not os.path.exists(target):
        print("target file not exist")
        return
    name = os.path.basename(target)
    f = MachOFile(target)
    if not f.valid:
        print("macho invalid")
        return
    for obj in f.obj:
        header = obj.header
        print("{} (architecture {})".format(name, get_arch(header.cpu_type, header.cpu_subtype)))
        if del_dylib(args, obj):
            need_update = True
    if need_update:
        path = args.output if args.output else args.target
        print("Successfully write to " + path)
        f.write(path)

def add_rpath(args, obj=None):
    need_update = False
    if obj:
        path = args.runpath
        command = RPathCommand.rpath(path)
        if args.index != -1:
            obj.add(command, args.index)
        else:
            obj.add(command)
        print("Successfully insert {}".format(path))
        return True
    target = args.target
    if not os.path.exists(target):
        print("target file not exist")
        return
    name = os.path.basename(target)
    f = MachOFile(target)
    if not f.valid:
        print("macho invalid")
        return
    for obj in f.obj:
        header = obj.header
        print("{} (architecture {})".format(name, get_arch(header.cpu_type, header.cpu_subtype)))
        if add_rpath(args, obj):
            need_update = True
    if need_update:
        path = args.output if args.output else args.target
        print("Successfully write to " + path)
        f.write(path)

def del_rpath(args, obj=None):
    pass

def list_dylib(args, obj=None):
    if obj:
        rpath_list = list()
        dylib_dict = {k:list() for k in dylib_keymap.values()}
        index_max = len(obj.commands)
        for index, cmd in enumerate(obj.commands):
            if cmd.command in dylib_keymap:
                dylib_type = dylib_keymap[cmd.command]
                dylib_dict[dylib_type].append({
                    "index": index,
                    "name": cmd.name,
                    "ver": cmd.current_version,
                    "compatver": cmd.compatibility_version,
                })
            elif cmd.command == LoadCommand.TYPE.RPATH:
                rpath_list.append({
                    "index": index,
                    "path": cmd.path
                })
        if rpath_list:
            print("  command rpath:")
            for item in rpath_list:
                print("    [{}/{}] {}".format(item["index"], index_max, item["path"]))
        for k in dylib_keymap.values():
            if not dylib_dict[k]:
                continue
            print("  command dylib {}:".format(k))
            for item in dylib_dict[k]:
                cov = version2str(item["ver"])
                cuv = version2str(item["compatver"])
                print("    [{}/{}] {} (compatibility version {}, current version {})".format(item["index"], index_max, item["name"], cov, cuv))
        return
    target = args.target
    if not os.path.exists(target):
        print("target file not exist")
        return
    name = os.path.basename(target)
    f = MachOFile(target)
    if not f.valid:
        print("macho invalid")
        return
    for obj in f.obj:
        header = obj.header
        print("{} (architecture {})".format(name, get_arch(header.cpu_type, header.cpu_subtype)))
        list_dylib(args, obj)
        print("")

if __name__ == "__main__":
    parser = argparse.ArgumentParser("optool " + ver, add_help=False)
    subparsers = parser.add_subparsers()
    adddylib_parser = subparsers.add_parser("add_dylib", add_help=False)
    chgdylib_parser = subparsers.add_parser("chg_dylib", add_help=False)
    deldylib_parser = subparsers.add_parser("del_dylib", add_help=False)
    addrpath_parser = subparsers.add_parser("add_rpath", add_help=False)
    delrpath_parser = subparsers.add_parser("del_rpath", add_help=False)
    info_parser = subparsers.add_parser("info", add_help=False)
    adddylib_parser.add_argument("-c", type=str, dest="command", required=True)
    adddylib_parser.add_argument("-p", type=str, dest="loadpath", required=True)
    adddylib_parser.add_argument("-i", type=int, dest="index", default=-1)
    adddylib_parser.add_argument("-t", type=str, dest="target", required=True)
    adddylib_parser.add_argument("-o", type=str, dest="output")
    adddylib_parser.set_defaults(func=add_dylib)
    chgdylib_parser.add_argument("-c", type=str, dest="command")
    chgdylib_parser.add_argument("-p", type=str, dest="loadpath", required=True)
    chgdylib_parser.add_argument("-r", type=str, dest="relace", required=True)
    chgdylib_parser.add_argument("-t", type=str, dest="target", required=True)
    chgdylib_parser.add_argument("-o", type=str, dest="output")
    chgdylib_parser.set_defaults(func=chg_dylib)
    deldylib_parser.add_argument("-c", type=str, dest="command")
    deldylib_parser.add_argument("-p", type=str, dest="loadpath", required=True)
    deldylib_parser.add_argument("-t", type=str, dest="target", required=True)
    deldylib_parser.add_argument("-o", type=str, dest="output")
    deldylib_parser.set_defaults(func=del_dylib)
    addrpath_parser.add_argument("-p", type=str, dest="runpath", required=True)
    addrpath_parser.add_argument("-i", type=int, dest="index", default=-1)
    addrpath_parser.add_argument("-t", type=str, dest="target", required=True)
    addrpath_parser.add_argument("-o", type=str, dest="output")
    addrpath_parser.set_defaults(func=add_rpath)
    delrpath_parser.add_argument("-p", type=str, dest="runpath", required=True)
    delrpath_parser.add_argument("-t", type=str, dest="target", required=True)
    delrpath_parser.add_argument("-o", type=str, dest="output")
    delrpath_parser.set_defaults(func=del_rpath)
    info_parser.add_argument("-t", type=str, dest="target", required=True)
    info_parser.set_defaults(func=list_dylib)
    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        HELP = parser.format_usage()
        HELP += "add_dylib -c <command> -p <loadpath> [-i <index>] -t <target> [-o <output>]    \n"
        HELP += "    Insert LC_LOAD command with specific loadpath into target binary           \n"
        HELP += "chg_dylib -c <command> -p <loadpath> [-r <replace>] -t <target> [-o <output>]  \n"
        HELP += "    Replace LC_LOAD command with specific loadpath from target binary          \n"
        HELP += "del_dylib [-c <command>] -p <loadpath> -t <target> [-o <output>]               \n"
        HELP += "    Remove LC_LOAD command with specific loadpath from target binary           \n"
        HELP += "add_rpath -p <runpath> [-i <index>] -t <target> [-o <output>]                  \n"
        HELP += "    Insert LC_RPATH command with specific runpath into target binary           \n"
        HELP += "del_rpath -p <runpath> -t <target> [-o <output>]                               \n"
        HELP += "    Remove LC_RPATH command with specific runpath from target binary           \n"
        HELP += "info -t <target>                                                               \n"
        HELP += "    show app dependent dylibs in target binary                                 \n"
        HELP += "\nOPTIONS:                                                                     \n"
        HELP += "    -t <target>    Input macho file                                            \n"
        HELP += "    -p <loadpath>  Dylib path to add_dylib or del_dylib                        \n"
        HELP += "    -c <command>   Type of load command                                        \n"
        HELP += "        id:        LC_ID_DYLIB                                                 \n"
        HELP += "        lazy:      LC_LAZY_LOAD_DYLIB                                          \n"
        HELP += "        load:      LC_LOAD_DYLIB                                               \n"
        HELP += "        reexport:  LC_REEXPORT_DYLIB                                           \n"
        HELP += "        upward:    LC_LOAD_UPWARD_DYLIB                                        \n"
        HELP += "        weak:      LC_LOAD_WEAK_DYLIB                                          \n"
        HELP += "    -o <path>      Output macho file, default to Input file                    \n"
        HELP += "    -i <index>     Insert position to add_dylib                                \n"
        HELP += "    -r <replace>   New path to replace for chg_dylib command                   \n"
        print(HELP)



'''
test:
python3 optool.py info -t /tmp/ls
python3 optool.py del_dylib -p /usr/lib/libutil.dylib -t /tmp/ls
python3 optool.py chg_dylib -p /usr/lib/libutil.dylib -r /usr/lib/test1.dylib -t /tmp/ls
python3 optool.py add_dylib -c weak -p /usr/lib/libutil.dylib -t /tmp/ls
'''


