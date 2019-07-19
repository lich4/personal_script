# -*- coding:utf-8 -*-
################################################################
#
#   Copyright (c) 2016 Baidu.com, Inc. All rights Reserved
#
################################################################
"""
this module is for analysing macho file
Authors:    lichao(lichao26@baidu.com)
Date:       2016/09/23
"""

import struct
import sys

MH_MAGIC = 0xfeedface
MH_CIGAM = 0xcefaedfe
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe
FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SYMSEG = 0x3
LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5
LC_LOADFVMLIB = 0x6
LC_IDFVMLIB = 0x7
LC_IDENT = 0x8
LC_FVMFILE = 0x9
LC_PREPAGE = 0xa
LC_DYSYMTAB = 0xb
LC_LOAD_DYLIB = 0xc
LC_ID_DYLIB = 0xd
LC_LOAD_DYLINKER = 0xe
LC_ID_DYLINKER = 0xf
LC_PREBOUND_DYLIB = 0x10
LC_ROUTINES = 0x11
LC_SUB_FRAMEWORK = 0x12
LC_SUB_UMBRELLA = 0x13
LC_SUB_CLIENT = 0x14
LC_SUB_LIBRARY = 0x15
LC_TWOLEVEL_HINTS = 0x16
LC_PREBIND_CKSUM = 0x17
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_SEGMENT_64 = 0x19
LC_ROUTINES_64 = 0x1a
LC_UUID = 0x1b
LC_RPATH = 0x8000001c
LC_CODE_SIGNATURE = 0x1d
LC_SEGMENT_SPLIT_INFO = 0x1e
LC_REEXPORT_DYLIB = 0x8000001f
LC_LAZY_LOAD_DYLIB = 0x20
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_FUNCTION_STARTS = 0x26
LC_DYLD_ENVIRONMENT = 0x27
LC_MAIN = 0x80000028
LC_DATA_IN_CODE = 0x29
LC_SOURCE_VERSION = 0x2A
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LINKER_OPTION = 0x2D
LC_LINKER_OPTIMIZATION_HINT = 0x2E
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30

MH_NOUNDEFS = 0x0
MH_INCRLINK = 0x1
MH_DYLDLINK = 0x2
MH_BINDATLOAD = 0x3
MH_PREBOUND = 0x4
MH_SPLIT_SEGS = 0x5
MH_LAZY_INIT = 0x6
MH_TWOLEVEL = 0x7
MH_FORCE_FLAT = 0x8
MH_NOMULTIDEFS = 0x9
MH_NOFIXPREBINDING = 0xA
MH_PREBINDABLE = 0xB
MH_ALLMODSBOUND = 0xC
MH_SUBSECTIONS_VIA_SYMBOLS = 0xD
MH_CANONICAL = 0xE
MH_WEAK_DEFINES = 0xF
MH_BINDS_TO_WEAK = 0x10
MH_ALLOW_STACK_EXECUTION = 0x11
MH_ROOT_SAFE = 0x12
MH_SETUID_SAFE = 0x13
MH_NO_REEXPORTED_DYLIBS = 0x14
MH_PIE = 0x15
MH_DEAD_STRIPPABLE_DYLIB = 0x16
MH_HAS_TLV_DESCRIPTORS = 0x17
MH_NO_HEAP_EXECUTION = 0x18
MH_APP_EXTENSION_SAFE = 0x19

CSMAGIC_BLOBWRAPPER = 0xfade0b01
CSMAGIC_REQUIREMENT = 0xfade0c00
CSMAGIC_REQUIREMENTS = 0xfade0c01
CSMAGIC_CODEDIRECTORY = 0xfade0c02
CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1
CSMAGIC_ENTITLEMENTS = 0xfade7171
CSSLOT_CODEDIRECTORY = 0
CSSLOT_REQUIREMENTS = 2
CSSLOT_ENTITLEMENTS = 5


class LoadCommand(object):
    """
    wrapper for correspoding structure
    """
    descript = "2I"
    strusize = 8
    cmd = 0
    cmdsize = 0

    all_load_commands_str = {
        LC_SEGMENT: "LC_SEGMENT",
        LC_SYMTAB: " LC_SYMTAB",
        LC_SYMSEG: " LC_SYMSEG",
        LC_SYMSEG: " LC_SYMSEG",
        LC_SYMSEG: " LC_SYMSEG",
        LC_LOADFVMLIB: " LC_LOADFVMLIB",
        LC_IDFVMLIB: " LC_IDFVMLIB",
        LC_IDENT: " LC_IDENT",
        LC_FVMFILE: " LC_FVMFILE",
        LC_PREPAGE: " LC_PREPAGE",
        LC_DYSYMTAB: " LC_DYSYMTAB",
        LC_LOAD_DYLIB: " LC_LOAD_DYLIB",
        LC_ID_DYLIB: " LC_ID_DYLIB",
        LC_LOAD_DYLINKER: " LC_LOAD_DYLINKER",
        LC_PREBOUND_DYLIB: " LC_PREBOUND_DYLIB",
        LC_ROUTINES: " LC_ROUTINES",
        LC_SUB_FRAMEWORK: " LC_SUB_FRAMEWORK",
        LC_SUB_UMBRELLA: " LC_SUB_UMBRELLA",
        LC_SUB_CLIENT: " LC_SUB_CLIENT",
        LC_SUB_LIBRARY: " LC_SUB_LIBRARY",
        LC_TWOLEVEL_HINTS: " LC_TWOLEVEL_HINTS",
        LC_PREBIND_CKSUM: " LC_PREBIND_CKSUM",
        LC_LOAD_WEAK_DYLIB: " LC_LOAD_WEAK_DYLIB",
        LC_SEGMENT_64: " LC_SEGMENT_64",
        LC_ROUTINES_64: " LC_ROUTINES_64",
        LC_UUID: " LC_UUID",
        LC_RPATH: " LC_RPATH",
        LC_CODE_SIGNATURE: " LC_CODE_SIGNATURE",
        LC_SEGMENT_SPLIT_INFO: " LC_SEGMENT_SPLIT_INFO",
        LC_REEXPORT_DYLIB: " LC_REEXPORT_DYLIB",
        LC_LAZY_LOAD_DYLIB: " LC_LAZY_LOAD_DYLIB",
        LC_ENCRYPTION_INFO: " LC_ENCRYPTION_INFO",
        LC_DYLD_INFO: " LC_DYLD_INFO",
        LC_DYLD_INFO_ONLY: " LC_DYLD_INFO_ONLY",
        LC_LOAD_UPWARD_DYLIB: " LC_LOAD_UPWARD_DYLIB",
        LC_VERSION_MIN_MACOSX: " LC_VERSION_MIN_MACOSX",
        LC_VERSION_MIN_IPHONEOS: " LC_VERSION_MIN_IPHONEOS",
        LC_FUNCTION_STARTS: " LC_FUNCTION_STARTS",
        LC_DYLD_ENVIRONMENT: " LC_DYLD_ENVIRONMENT",
        LC_MAIN: " LC_MAIN",
        LC_DATA_IN_CODE: " LC_DATA_IN_CODE",
        LC_SOURCE_VERSION: " LC_SOURCE_VERSION",
        LC_DYLIB_CODE_SIGN_DRS: " LC_DYLIB_CODE_SIGN_DRS",
        LC_ENCRYPTION_INFO_64: " LC_ENCRYPTION_INFO_64",
        LC_LINKER_OPTION: " LC_LINKER_OPTION",
        LC_LINKER_OPTIMIZATION_HINT: " LC_LINKER_OPTIMIZATION_HINT",
    }

    def get_cmd_description(self):
        """
        output description for structure
        """
        return self.all_load_commands_str[self.cmd]


class Section(object):
    """
    wrapper for correspoding structure
    """
    descript = "16s16s9I"
    strusize = 68
    sectname = ""
    segname = ""
    addr = 0
    size = 0
    offset = 0
    align = 0
    reloff = 0
    nreloc = 0
    flags = 0
    reserved1 = 0
    reserved2 = 0

    #    def __init(self, type):
    #        # type=0:86   type=1:64
    #        if type == 0:
    #            self.descript = "16s16s7I"
    #            self.strusize = 60
    #        else:
    #            self.descript = "16s16s2Q5I"
    #            self.strusize = 68
    #        self.type = type

    def get_section_description(self):
        """
        output description for structure
        """
        str = "secname=%s memaddr=%08x memsize=%08x " % (self.sectname, self.addr, self.size)
        str = str + "fileoffset=%08x flag=%08x" % (self.offset, self.flags)
        return str


class EncryptionInfoCommand(LoadCommand):
    """
    wrapper for correspoding structure
    """
    descript = "5I"
    strusize = 20
    cryptoff = 0
    cryptsize = 0
    cryptid = 0

    def get_encrypt_description(self):
        """
        output description for structure
        """
        return "ENCRYPT-FILE:cryptoff=%08x cryptsize=%08x cryptid=%d" % \
               (self.cryptoff, self.cryptsize, self.cryptid)


class DylibCommand(LoadCommand):
    """
    wrapper for correspoding structure
    """
    descript = "3I"
    strusize = 12
    nameoff = 0

    def get_dylib_description(self, data):
        """
        output description for structure
        """
        len = self.cmdsize - self.nameoff
        str, = struct.unpack("%ds" % len, data[self.nameoff:])
        return str.replace("\\x00", "")


class SegmentCommand(LoadCommand):
    """
    wrapper for correspoding structure
    """
    descript = "2I16s8I"
    strusize = 56
    segname = ""
    vmaddr = 0
    vmsize = 0
    fileoff = 0
    filesize = 0
    maxprot = 0
    initprot = 0
    nsects = 0
    flags = 0
    sections = []

    #    def __init__(self):
    #        type=0:86   type=1:64
    #        if type == 0:
    #            self.descript = ""
    #            self.strusize = 56
    #        else:
    #            self.descript = "2I16s4Q2i2I"
    #            self.strusize = 72
    #        self.type = type

    def get_vm_prot_flag(self, flag):
        """
        get vm flag
        """
        str = ""
        if flag == 0:
            str = "VM_PROT_NONE"
        else:
            if flag & 1:
                str = str + "VM_PROT_READ "
            elif flag & 2:
                str = str + "VM_PROT_WRITE "
            elif flag & 3:
                str = str + "VM_PROT_EXECUTE "
        return str

    def get_segment_flag(self):
        """
        get segment flag
        """
        str = ""
        if self.flags == 0:
            str = "NONE"
        if self.flags & 1:
            str = str + "SG_HIGHVM "
        if self.flags & 2:
            str = str + "SG_FVMLIB"
        if self.flags & 4:
            str = str + "SG_NORELOC"
        if self.flags & 8:
            str = str + "SG_PROTECTED_VERSION_1"
        return str

    def get_segment_description(self):
        """
        output description for structure
        """
        str = "segname:%s vmaddr:%08x vmsize:%08x " % (self.segname, self.vmaddr, self.vmsize)
        str = str + "fileoff:%08x filesize:%08x sectnum:%d " % (self.fileoff, self.filesize, \
            self.nsects)
        str = str + "maxpro:%s " % self.get_vm_prot_flag(self.maxprot)
        str = str + "initpro:%s " % self.get_vm_prot_flag(self.initprot)
        str = str + "flag:%s" % self.get_segment_flag()
        return str


class MachHeader(object):
    """
    wrapper for correspoding structure
    """
    descipt = "7I"
    strusize = 28
    magic = 0
    cputype = 0
    cpusubtype = 0
    filetype = 0
    ncmds = 0
    sizeofcmds = 0
    flags = 0
    commands = []

    all_flag_str = [
        " MH_NOUNDEFS",
        " MH_INCRLINK",
        " MH_DYLDLINK",
        " MH_BINDATLOAD",
        " MH_PREBOUND",
        " MH_SPLIT_SEGS",
        " MH_LAZY_INIT",
        " MH_TWOLEVEL",
        " MH_FORCE_FLAT",
        " MH_NOMULTIDEFS",
        " MH_NOFIXPREBINDING",
        " MH_PREBINDABLE",
        " MH_ALLMODSBOUND",
        " MH_SUBSECTIONS_VIA_SYMB",
        " MH_CANONICAL",
        " MH_WEAK_DEFINES",
        " MH_BINDS_TO_WEAK",
        " MH_ALLOW_STACK_EXECUTIO",
        " MH_ROOT_SAFE",
        " MH_SETUID_SAFE",
        " MH_NO_REEXPORTED_DYLIBS",
        " MH_PIE",
        " MH_DEAD_STRIPPABLE_DYLI",
        " MH_HAS_TLV_DESCRIPTORS",
        " MH_NO_HEAP_EXECUTION",
        " MH_APP_EXTENSION_SAFE",
    ]

    def get_filetype_description(self):
        """
        get file type info
        """
        return [
            "None",
            "MH_OBJECT",
            "MH_EXECUTE",
            "MH_FVMLIB",
            "MH_CORE",
            "MH_PRELOAD",
            "MH_DYLIB",
            "MH_DYLINKER",
            "MH_BUNDLE",
            "MH_DYLIB_STUB",
            "MH_DYLIB_STUB",
            "MH_KEXT_BUNDLE"
        ][self.filetype]

    def get_flagdescription(self):
        """
        get file settings
        """
        flagstr = ""
        bit = 0
        flags = self.flags
        while flags != 0:
            if (flags & 1) != 0:
                flagstr = flagstr + self.all_flag_str[bit] + " "
            bit = bit + 1
            flags = flags >> 1
        return flagstr


class FatHeader(object):
    """
    wrapper for correspoding structure
    """
    descipt = "2I"
    strusize = 8
    magic = 0
    nfat_arch = 0


class FatArch(object):
    """
    wrapper for correspoding structure
    """
    descipt = "5I"
    strusize = 20
    cputype = 0
    cpusubtype = 0
    offset = 0
    size = 0
    align = 0


def extract_single_macho(bytes, machobytes):
    """
    Extract info from a single mach-o structure
    :param bytes: while file data
    :param machobytes: current mach-o data
    """
    magic, = struct.unpack("<I", machobytes[0: 4])
    if magic == MH_MAGIC or magic == MH_MAGIC_64:
        prefix = "<"
    elif magic == MH_CIGAM or magic == MH_CIGAM_64:
        prefix = ">"
    else:
        raise Exception("magic wrong")
    mh = MachHeader()
    mh.magic, mh.cputype, mh.cpusubtype, mh.filetype, mh.ncmds, mh.sizeofcmds, mh.flags, \
        = struct.unpack(prefix + mh.descipt, machobytes[0: mh.strusize])
    if dump_macho == 1:
        print "TYPE:%s\nFLAG:%s\nCMDNUM:%d" % (
            mh.get_filetype_description(), mh.get_flagdescription(), (mh.sizeofcmds))
    if remove_pie == 1:
        mh.flags = mh.flags & ~0x200000
        newdata = struct.pack(prefix + mh.descipt, mh.magic, mh.cputype, mh.cpusubtype, \
                              mh.filetype, mh.ncmds, mh.sizeofcmds, mh.flags)
        machobytes = newdata + machobytes[mh.strusize:]
    offset = mh.strusize
    for cmdindex in range(0, mh.ncmds):
        lc = LoadCommand()
        lc.cmd, lc.cmdsize, = struct.unpack(prefix + lc.descript, \
                                            machobytes[offset: offset + lc.strusize])
        if lc.cmdsize <= lc.strusize:
            raise Exception("bad cmd")
        if lc.cmd not in lc.all_load_commands_str:
            raise Exception("bad cmd %d" % lc.cmd)
        if dump_macho == 1:
            print "\t", lc.get_cmd_description()
        if lc.cmd == LC_SEGMENT:
            sc = SegmentCommand()
            sc.cmd, sc.cmdsize, sc.segname, sc.vmaddr, sc.vmsize, sc.fileoff, sc.filesize, \
            sc.maxprot, sc.initprot, sc.nsects, sc.flags, = \
                struct.unpack(prefix + sc.descript, machobytes[offset: offset + sc.strusize])
            if dump_macho == 1:
                print "\t\t", sc.get_segment_description()
            if sc.segname == "__RESTRICT\0\0\0\0\0\0" and remove_restrict == 1:
                sc.segname = sc.segname[0: 2] + "X" + sc.segname[3:]
                newdata = struct.pack(prefix + sc.descript, sc.cmd, sc.cmdsize, sc.segname, \
     sc.vmaddr, sc.vmsize, sc.fileoff, sc.filesize, sc.maxprot, sc.initprot, sc.nsects, sc.flags)
                machobytes = machobytes[0: offset] + newdata + machobytes[offset + sc.strusize:]
            for i in range(0, sc.nsects):
                sec = Section()
                secoff = offset + sc.strusize + i * sec.strusize
                sec.sectname, sec.segname, sec.addr, sec.size, sec.offset, sec.align, \
                sec.reloff, sec.nreloc, sec.flags, sec.reserved1, sec.reserved2 = \
                    struct.unpack(prefix + sec.descript, machobytes[secoff: secoff + sec.strusize])
                if dump_macho == 1:
                    print "\t\t\t", sec.get_section_description()
                if sec.segname == "__RESTRICT\0\0\0\0\0\0" and remove_restrict == 1:
                    sec.segname = sec.segname[0: 2] + "X" + sec.segname[3:]
                    sec.sectname = sec.sectname[0: 2] + "X" + sec.sectname[3:]
                    d = struct.pack(prefix + sec.descript, sec.sectname, sec.segname, \
                        sec.addr, sec.size, sec.offset, sec.align, sec.reloff, sec.nreloc, \
                        sec.flags, sec.reserved1, sec.reserved2)
                    machobytes = machobytes[0: secoff] + d + machobytes[secoff + sec.strusize:]
        elif lc.cmd == LC_ENCRYPTION_INFO:
            ec = EncryptionInfoCommand()
            ec.cmd, ec.cmdsize, ec.cryptoff, ec.cryptsize, ec.cryptid, = \
                struct.unpack(prefix + ec.descript, machobytes[offset: offset + ec.strusize])
            if dump_macho == 1:
                print "\t\t", ec.get_encrypt_description()
        elif lc.cmd == LC_LOAD_DYLIB or lc.cmd == LC_LOAD_WEAK_DYLIB:
            dc = DylibCommand()
            dc.cmd, dc.cmdsize, dc.nameoff = \
                struct.unpack(prefix + dc.descript, machobytes[offset: offset + dc.strusize])
            if dump_macho == 1:
                print "\t\t", dc.get_dylib_description(machobytes[offset: offset + dc.cmdsize])
        offset = offset + lc.cmdsize
    if len(inject_dylib_path) > 0:
        for dylib in inject_dylib_path:
            # first we format dylib-path with 4-byte alignment
            left = len(dylib) % 4
            dylib = dylib + ["\0\0\0\0", "\0\0\0", "\0\0", "\0"][left]
            # then we construct a LC_LOAD_DYLIB command
            cmd = LC_LOAD_DYLIB
            cmdsize = 24 + len(dylib)
            nameoff = 24
            timestamps = 2
            current_version = 0x10000
            compatibility_version = 0x10000
            newdata = struct.pack("6I%ds" % len(dylib), cmd, cmdsize, nameoff, timestamps, \
                                  current_version, compatibility_version, dylib)
            # update command data
            machobytes = machobytes[0: mh.strusize + mh.sizeofcmds] + newdata + \
                         machobytes[mh.strusize + mh.sizeofcmds + cmdsize:]
            mh.ncmds = mh.ncmds + 1
            mh.sizeofcmds = mh.sizeofcmds + dc.cmdsize
        # update header
        newdata = struct.pack(prefix + mh.descipt, mh.magic, mh.cputype, mh.cpusubtype, \
                              mh.filetype, mh.ncmds, mh.sizeofcmds, mh.flags)
        machobytes = newdata + machobytes[mh.strusize:]
    return machobytes


def get_cputype_description(cputype):
    """
    get cpu type
    """
    cpustr = ""
    arch = cputype & 0x1000000
    maintype = cputype & 0xf
    if maintype == 0x7:
        if arch == 0x0000000:
            cpustr = "CPU_TYPE_X86"
        elif arch == 0x1000000:
            cpustr = "CPU_TYPE_X86_64"
    elif maintype == 0xC:
        if arch == 0x0000000:
            cpustr = "CPU_TYPE_ARM"
        elif arch == 0x1000000:
            cpustr = "CPU_TYPE_ARM64"
    else:
        cpustr = "UNKNOWN"
    return cpustr


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print "Usage:%s [options] targetpath\noptions:" % sys.argv[0]
        print "\t--dump-macho : dump macho base info"
        print "\t--remove-pie : remove position-independent-executable flag"
        print "\t--remove-restrict : remove segments with restrict attribute"
        print "\t--injectdylib=path : inject a dylib to the import table of the macho file"
        sys.exit(0)
    dump_macho = 0
    dump_objc = 0
    remove_pie = 0
    remove_restrict = 0
    target_path = sys.argv[-1]
    inject_dylib_path = []
    for argv in sys.argv:
        if argv == "--dump-macho":
            dump_macho = 1
        elif argv == "--remove-pie":
            remove_pie = 1
        elif argv == "--remove-restrict":
            remove_restrict = 1
        elif argv.find("--injectdylib") != -1:
            tmp = argv.split("=")
            if len(tmp) == 2:
                inject_dylib_path.append(tmp[1])

    file = open(target_path, 'rb')
    bytes = file.read()
    file.close()
    magic, = struct.unpack("<I", bytes[0: 4])
    resultdata = ""
    if magic == MH_MAGIC or magic == MH_CIGAM:
        # magic == MH_CIGAM_64 or magic == MH_MAGIC_64
        resultdata = extract_single_macho(bytes, bytes)
    elif magic == FAT_MAGIC or magic == FAT_CIGAM:
        # we only care about armv7 binary
        if magic == FAT_MAGIC:
            prefix = "<"
        else:
            prefix = ">"
        fh = FatHeader()
        fh.magic, fh.nfat_arch, = struct.unpack(prefix + fh.descipt, bytes[0: fh.strusize])
        for i in range(0, fh.nfat_arch):
            fa = FatArch()
            fatdata = bytes[fh.strusize + i * fa.strusize: fh.strusize + (i + 1) * fa.strusize]
            fa.cputype, fa.cpusubtype, fa.offset, fa.size, fa.align, = \
                struct.unpack(prefix + fa.descipt, fatdata)
            if get_cputype_description(fa.cputype) == "CPU_TYPE_ARM":
                resultdata = extract_single_macho(bytes, bytes[fa.offset: fa.offset + fa.size])
                break
    else:
        raise Exception("magic wrong")

    # we may want to update the file
    if resultdata != "":
        file = open(target_path + "_patched", 'wb')
        file.write(resultdata)
        file.close()
        print "update to " + target_path + "_patched"
