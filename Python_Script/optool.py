#!python3.9

import argparse
import lief
import os
import sys
import tempfile
from lief.MachO import LOAD_COMMAND_TYPES as LCT
from lief.MachO import CPU_TYPES as CT

ver = "v1.0"

EMPTY_ENT = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
</dict>
</plist>
"""

dylib_keymap = {
    LCT.ID_DYLIB:           "id", 
    LCT.LOAD_DYLIB:         "load", 
    LCT.REEXPORT_DYLIB:     "reexport", 
    LCT.LOAD_WEAK_DYLIB:    "weak", 
    LCT.LAZY_LOAD_DYLIB:    "lazy", 
    LCT.LOAD_UPWARD_DYLIB:  "upwardoad", 
    LCT.PREBOUND_DYLIB:     "prebound",
}

dylib_ctor_map = {
    "id":       lief.MachO.DylibCommand.id_dylib,
    "load":     lief.MachO.DylibCommand.load_dylib,
    "reexport": lief.MachO.DylibCommand.reexport_dylib,
    "weak":     lief.MachO.DylibCommand.weak_lib,
    "lazy":     lief.MachO.DylibCommand.lazy_load_dylib,
    "upwardoad":lief.MachO.DylibCommand.load_upward_dylib,
}

version2str = lambda version: ".".join([str(i) for i in version])
version2int = lambda version: (version[2]) | (version[1] << 8) | (version[0] << 16)

def get_arch(cpu_type, cpu_subtype):
    cpu_keymap = {
        CT.ARM: "arm",
        CT.ARM64: "arm64",
        CT.I386: "i386",
        CT.x86: "x86",
        CT.x86_64: "x86_64",
    }
    if cpu_type not in cpu_keymap:
        return "unknown"
    s = cpu_keymap[cpu_type]
    if cpu_type == CT.ARM64 and cpu_subtype > 0:
        s += "e abi=" + hex(cpu_subtype)
    return s

class MachOFile:
    def __init__(self, path):
        self.path = path
        self.valid = lief.is_macho(path)
        if self.valid:
            self.obj = lief.MachO.parse(path, config=lief.MachO.ParserConfig.quick)
            if lief.MachO.is_fat(path):
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

def inst_dylib(args, obj=None):
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
        if inst_dylib(args, obj):
            need_update = True
    if need_update:
        path = args.output if args.output else args.target
        print("Successfully write to " + path)
        f.write(path)

def replace_dylib(args, obj=None):
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
                new_cmd = ctor(args.replace, cmd.timestamp, version2int(cmd.current_version), version2int(cmd.compatibility_version))
                need_update = True
                break
        if to_del_index:
            obj.remove_command(to_del_index)
            obj.add(new_cmd, to_del_index)
            print("Successfully update [{}/{}] {} -> {}".format(index, index_max, args.loadpath, args.replace))
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
        if replace_dylib(args, obj):
            need_update = True
    if need_update:
        path = args.output if args.output else args.target
        print("Successfully write to " + path)
        f.write(path)

def uninst_dylib(args, obj=None):
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
        if uninst_dylib(args, obj):
            need_update = True
    if need_update:
        path = args.output if args.output else args.target
        print("Successfully write to " + path)
        f.write(path)

def list_dylib(args, obj=None):
    if obj:
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
        for k in dylib_keymap.values():
            if len(dylib_dict[k]) == 0:
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
    inst_parser = subparsers.add_parser("install", add_help=False, help="Inserts an LC_LOAD command into the target binary with specific loadpath")
    replace_parser = subparsers.add_parser("replace", add_help=False, help="Replace any LC_LOAD commands which point to a given loadpath from the target binary")
    uninst_parser = subparsers.add_parser("uninstall", add_help=False, help="Removes any LC_LOAD commands which point to a given loadpath from the target binary")
    list_parser = subparsers.add_parser("list", add_help=False, help="Show app dependency dylibs in target binary")
    inst_parser.add_argument("-c", type=str, dest="command", required=True)
    inst_parser.add_argument("-p", type=str, dest="loadpath", required=True)
    inst_parser.add_argument("-i", type=int, dest="index", default=-1)
    inst_parser.add_argument("-t", type=str, dest="target", required=True)
    inst_parser.add_argument("-o", type=str, dest="output")
    inst_parser.set_defaults(func=inst_dylib)
    replace_parser.add_argument("-c", type=str, dest="command")
    replace_parser.add_argument("-p", type=str, dest="loadpath", required=True)
    replace_parser.add_argument("-r", type=str, dest="replace", required=True)
    replace_parser.add_argument("-t", type=str, dest="target", required=True)
    replace_parser.add_argument("-o", type=str, dest="output")
    replace_parser.set_defaults(func=replace_dylib)
    uninst_parser.add_argument("-c", type=str, dest="command")
    uninst_parser.add_argument("-p", type=str, dest="loadpath", required=True)
    uninst_parser.add_argument("-t", type=str, dest="target", required=True)
    uninst_parser.add_argument("-o", type=str, dest="output")
    uninst_parser.set_defaults(func=uninst_dylib)
    list_parser.add_argument("-t", type=str, dest="target", required=True)
    list_parser.set_defaults(func=list_dylib)
    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        HELP = parser.format_usage()
        HELP += "install -c <command> -p <loadpath> [-i <index>] -t <target> [-o <output>]      \n"
        HELP += "    Insert LC_LOAD command into target binary with specific loadpath           \n"
        HELP += "replace -c <command> -p <loadpath> [-r <replace>] -t <target> [-o <output>]    \n"
        HELP += "    Replace LC_LOAD command from target binary with specific loadpath          \n"
        HELP += "uninstall [-c <command>] -p <loadpath> -t <target> [-o <output>]               \n"
        HELP += "    Remove LC_LOAD command from target binary with specific loadpath           \n"
        HELP += "list -t <target>                                                         \n"
        HELP += "    show app dependent dylibs in target binary                                 \n"
        HELP += "\nOPTIONS:                                                                     \n"
        HELP += "    -t <target>    Input macho file                                            \n"
        HELP += "    -p <loadpath>  Dylib path to install or uninstall                          \n"
        HELP += "    -c <command>   Type of load command                                        \n"
        HELP += "        id:        LC_ID_DYLIB                                                 \n"
        HELP += "        lazy:      LC_LAZY_LOAD_DYLIB                                          \n"
        HELP += "        load:      LC_LOAD_DYLIB                                               \n"
        HELP += "        reexport:  LC_REEXPORT_DYLIB                                           \n"
        HELP += "        upward:    LC_LOAD_UPWARD_DYLIB                                        \n"
        HELP += "        weak:      LC_LOAD_WEAK_DYLIB                                          \n"
        HELP += "    -o <path>      Output macho file, default to Input file                    \n"
        HELP += "    -i <index>     Insert position to install                                  \n"
        HELP += "    -r <path>      Old path to replace for install command                     \n"
        print(HELP)

'''
test:
python3 optool.py list -t /tmp/ls
python3 optool.py uninstall -p /usr/lib/libutil.dylib -t /tmp/ls
python3 optool.py replace -p /usr/lib/libutil.dylib -r /usr/lib/test1.dylib -t /tmp/ls
python3 optool.py install -c weak -p /usr/lib/libutil.dylib -t /tmp/ls
'''

