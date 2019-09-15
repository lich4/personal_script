# -*- coding: utf-8 -*-

import os
import struct
import sys


def pad(s, align): return s + '\0' * (align - len(s) % align)


''' macho constants'''
FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca
FAT_MAGIC_64 = 0xcafebabf
FAT_CIGAM_64 = 0xbfbafeca

MH_MAGIC = 0xfeedface
MH_CIGAM = 0xcefaedfe
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe

MH_EXECUTE = 0x2
MH_DYLIB = 0x6

CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_X86 = 0x7
CPU_TYPE_X86_64 = (CPU_TYPE_X86 | CPU_ARCH_ABI64)
CPU_TYPE_ARM = 0xC
CPU_TYPE_ARM64 = (CPU_TYPE_ARM | CPU_ARCH_ABI64)

LC_REQ_DYLD = 0x80000000
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
LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD)
LC_SEGMENT_64 = 0x19
LC_ROUTINES_64 = 0x1a
LC_UUID = 0x1b
LC_RPATH = (0x1c | LC_REQ_DYLD)
LC_CODE_SIGNATURE = 0x1d
LC_SEGMENT_SPLIT_INFO = 0x1e
LC_REEXPORT_DYLIB = (0x1f | LC_REQ_DYLD)
LC_LAZY_LOAD_DYLIB = 0x20
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = (0x22 | LC_REQ_DYLD)
LC_LOAD_UPWARD_DYLIB = (0x23 | LC_REQ_DYLD)
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_FUNCTION_STARTS = 0x26
LC_DYLD_ENVIRONMENT = 0x27
LC_MAIN = (0x28 | LC_REQ_DYLD)
LC_DATA_IN_CODE = 0x29
LC_SOURCE_VERSION = 0x2A
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LINKER_OPTION = 0x2D
LC_LINKER_OPTIMIZATION_HINT = 0x2E
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_NOTE = 0x31
LC_BUILD_VERSION = 0x32

tostr = {
    'CPU': {
        CPU_TYPE_X86: 'CPU_TYPE_X86',
        CPU_TYPE_X86_64: 'CPU_TYPE_X86_64',
        CPU_TYPE_ARM: 'CPU_TYPE_ARM',
        CPU_TYPE_ARM64: 'CPU_TYPE_ARM64',
    },
    'MH': {
        MH_EXECUTE: 'MH_EXECUTE',
        MH_DYLIB: 'MH_DYLIB'
    },
    'LC': {
        LC_SEGMENT: 'LC_SEGMENT',
        LC_SYMTAB: 'LC_SYMTAB',
        LC_SYMSEG: 'LC_SYMSEG',
        LC_THREAD: 'LC_THREAD',
        LC_UNIXTHREAD: 'LC_UNIXTHREAD',
        LC_LOADFVMLIB: 'LC_LOADFVMLIB',
        LC_IDFVMLIB: 'LC_IDFVMLIB',
        LC_IDENT: 'LC_IDENT',
        LC_FVMFILE: 'LC_FVMFILE',
        LC_PREPAGE: 'LC_PREPAGE',
        LC_DYSYMTAB: 'LC_DYSYMTAB',
        LC_LOAD_DYLIB: 'LC_LOAD_DYLIB',
        LC_ID_DYLIB: 'LC_ID_DYLIB',
        LC_LOAD_DYLINKER: 'LC_LOAD_DYLINKER',
        LC_ID_DYLINKER: 'LC_ID_DYLINKER',
        LC_LOAD_WEAK_DYLIB: 'LC_LOAD_WEAK_DYLIB',
        LC_SEGMENT_64: 'LC_SEGMENT_64',
        LC_ROUTINES_64: 'LC_ROUTINES_64',
        LC_UUID: 'LC_UUID',
        LC_RPATH: 'LC_RPATH',
        LC_CODE_SIGNATURE: 'LC_CODE_SIGNATURE',
        LC_SEGMENT_SPLIT_INFO: 'LC_SEGMENT_SPLIT_INFO',
        LC_REEXPORT_DYLIB: 'LC_REEXPORT_DYLIB',
        LC_LAZY_LOAD_DYLIB: 'LC_LAZY_LOAD_DYLIB',
        LC_ENCRYPTION_INFO: 'LC_ENCRYPTION_INFO',
        LC_DYLD_INFO: 'LC_DYLD_INFO',
        LC_DYLD_INFO_ONLY: 'LC_DYLD_INFO_ONLY',
        LC_LOAD_UPWARD_DYLIB: 'LC_LOAD_UPWARD_DYLIB',
        LC_VERSION_MIN_MACOSX: 'LC_VERSION_MIN_MACOSX',
        LC_VERSION_MIN_IPHONEOS: 'LC_VERSION_MIN_IPHONEOS',
        LC_FUNCTION_STARTS: 'LC_FUNCTION_STARTS',
        LC_DYLD_ENVIRONMENT: 'LC_DYLD_ENVIRONMENT',
        LC_MAIN: 'LC_MAIN',
        LC_DATA_IN_CODE: 'LC_DATA_IN_CODE',
        LC_SOURCE_VERSION: 'LC_SOURCE_VERSION',
        LC_DYLIB_CODE_SIGN_DRS: 'LC_DYLIB_CODE_SIGN_DRS',
        LC_ENCRYPTION_INFO_64: 'LC_ENCRYPTION_INFO_64',
        LC_LINKER_OPTION: 'LC_LINKER_OPTION',
        LC_LINKER_OPTIMIZATION_HINT: 'LC_LINKER_OPTIMIZATION_HINT',
        LC_VERSION_MIN_TVOS: 'LC_VERSION_MIN_TVOS',
        LC_VERSION_MIN_WATCHOS: 'LC_VERSION_MIN_WATCHOS',
        LC_NOTE: 'LC_NOTE',
        LC_BUILD_VERSION: 'LC_BUILD_VERSION',
    }
}

''' elf constants'''


class fat_arch(object):
    size = 20

    def __init__(self, data, le):
        if le:
            self.cputype, self.cpusubtype, self.offset, self.size, self.align = \
                struct.unpack("<5I", data[0:20])
        else:
            self.cputype, self.cpusubtype, self.offset, self.size, self.align = \
                struct.unpack(">5I", data[0:20])

    def dump(self):
        if le:
            return struct.pack("<5I", self.cputype, self.cpusubtype, self.offset, self.size,
                               self.align)
        else:
            return struct.pack(">5I", self.cputype, self.cpusubtype, self.offset, self.size,
                               self.align)


class fat_header(object):
    def __init__(self, data):
        sign, = struct.unpack("<I", data[0:4])
        if sign in [FAT_MAGIC, FAT_MAGIC_64]:
            self.le = True
            self.sign, self.nfat_arch = struct.unpack("<2I", data[0:8])
        elif sign in [FAT_CIGAM, FAT_CIGAM_64]:
            self.le = False
            self.sign, self.nfat_arch = struct.unpack(">2I", data[0:8])
        self.fat_archs = list()
        for i in range(0, self.nfat_arch):
            self.fat_archs.append(
                fat_arch(data[8+fat_arch.size*i:8+fat_arch.size*(i+1)], self.le))

    def __len__(self):
        return 8 + self.nfat_arch * fat_arch.size

    def __str__(self):
        s = 'fat_header:\n'
        s += '  nfat_arch=%d\n' % self.nfat_arch
        for i in range(0, self.nfat_arch):
            s += '  cputype=%s cpusubtype=%x offset=%x size=%x align=%x\n' % (
                tostr['CPU'][self.fat_archs[i].cputype],
                self.fat_archs[i].cpusubtype,
                self.fat_archs[i].offset,
                self.fat_archs[i].size,
                self.fat_archs[i].align)
        return s

    def dump(self):
        data = b''
        if self.le:
            data += struct.pack("<2I", self.sign, self.nfat_arch)
        else:
            data += struct.pack(">2I", self.sign, self.nfat_arch)
        for i in range(0, self.nfat_arch):
            data += self.fat_archs[i].dump()
        return data


class load_command(object):
    @staticmethod
    def get_cmd_size(data, le):
        if le:
            return struct.unpack("<2I", data[0:8])
        else:
            return struct.unpack(">2I", data[0:8])

    def __init__(self, data, le):
        self.le = le
        self.data = data
        if self.le:
            self.cmd, self.cmdsize = struct.unpack("<2I", data[0:8])
        else:
            self.cmd, self.cmdsize = struct.unpack(">2I", data[0:8])

    def __len__(self):
        return self.cmdsize

    def __str__(self):
        return ''

    def dump(self):
        if self.le:
            return self.data
        else:
            return self.data


class dylib_command(load_command):
    def __init__(self, *args):
        if args[0] == 1:
            self.path = pad(args[1], 4).encode('utf-8')
            self.le = args[2]
            self.cmd = LC_LOAD_DYLIB
            self.cmdsize = 0x18 + len(self.path)
            self.offset = 0x18
            self.timestamp = 0x2
            self.current_version = 0x10000
            self.compatibility_version = 0x10000
            if self.le:
                self.data = struct.pack("<6I%ds" % len(self.path), self.cmd, self.cmdsize, self.offset,
                                        self.timestamp, self.current_version, self.compatibility_version, self.path)
            else:
                self.data = struct.pack(">6I%ds" % len(self.path), self.cmd, self.cmdsize, self.offset,
                                        self.timestamp, self.current_version, self.compatibility_version, self.path)
        elif args[0] == 0:
            self.data = args[1]
            self.le = args[2]
            pathlen = len(self.data) - 0x18
            if self.le:
                self.cmd, self.cmdsize, self.offset, self.timestamp, self.current_version, \
                    self.compatibility_version, self.path = struct.unpack(
                        "<6I%ds" % pathlen, self.data)
            else:
                self.cmd, self.cmdsize, self.offset, self.timestamp, self.current_version, \
                    self.compatibility_version, self.path = struct.unpack(
                        ">6I%ds" % pathlen, self.data)

    def __str__(self):
        return self.path.split(b'\0')[0].decode('utf-8')

    def dump(self):
        if self.le:
            return struct.pack("<6I%ds" % len(self.path), self.cmd, self.cmdsize, self.offset,
                               self.timestamp, self.current_version, self.compatibility_version, self.path)
        else:
            return struct.pack(">6I%ds" % len(self.path), self.cmd, self.cmdsize, self.offset,
                               self.timestamp, self.current_version, self.compatibility_version, self.path)


class mach_header(object):
    def __init__(self, data):
        sign, = struct.unpack("<I", data[0:4])
        if sign == MH_MAGIC:
            self.le = True
            self.bit64 = False
        elif sign == MH_CIGAM:
            self.le = False
            self.bit64 = False
        elif sign == MH_MAGIC_64:
            self.le = True
            self.bit64 = True
        elif sign == MH_CIGAM_64:
            self.le = False
            self.bit64 = True
        self.cmds = list()
        if self.bit64:
            if self.le:
                self.magic, self.cputype, self.cpusubtype, self.filetype, self.ncmds, \
                    self.sizeofcmds, self.flags, self.reserved = struct.unpack(
                        "<8I", data[0:32])
            else:
                self.magic, self.cputype, self.cpusubtype, self.filetype, self.ncmds, \
                    self.sizeofcmds, self.flags, self.reserved = struct.unpack(
                        ">8I", data[0:32])
            offset = 32
        else:
            if self.le:
                self.magic, self.cputype, self.cpusubtype, self.filetype, self.ncmds, \
                    self.sizeofcmds, self.flags = struct.unpack(
                        "<7I", data[0:28])
            else:
                self.magic, self.cputype, self.cpusubtype, self.filetype, self.ncmds, \
                    self.sizeofcmds, self.flags = struct.unpack(
                        ">7I", data[0:28])
            offset = 28
        for i in range(0, self.ncmds):
            cmd, cmdsize = load_command.get_cmd_size(
                data[offset:offset+8], self.le)
            if cmd == LC_LOAD_DYLIB:
                lc = dylib_command(0, data[offset:offset+cmdsize], self.le)
            else:
                lc = load_command(data[offset:offset+cmdsize], self.le)
            self.cmds.append(lc)
            offset += cmdsize

    def add_header(self, header):
        self.cmds.append(header)
        self.ncmds += 1
        self.sizeofcmds += header.cmdsize

    def rm_header(self, header):
        self.ncmds -= 1
        self.sizeofcmds -= header.cmdsize
        self.mh.cmds.remove(cmd)

    def __len__(self):
        if self.bit64:
            return 32 + self.sizeofcmds
        else:
            return 28 + self.sizeofcmds

    def __str__(self):
        s = 'macho_header:\n'
        s += '  cputype=%s cpusubtype=%x filetype=%s ncmds=%d sizeofcmds=%x flags=%x\n' % (
            tostr['CPU'][self.cputype],
            self.cpusubtype,
            tostr['MH'][self.filetype],
            self.ncmds,
            self.sizeofcmds,
            self.flags)
        for cmd in self.cmds:
            s += '    cmd=%s cmdsize=%x %s\n' % (
                tostr['LC'][cmd.cmd], cmd.cmdsize, cmd.__str__())
        return s

    def dump(self):
        data = b''
        if self.bit64:
            if self.le:
                data += struct.pack("<8I", self.magic, self.cputype, self.cpusubtype,
                                      self.filetype, self.ncmds, self.sizeofcmds, self.flags, self.reserved)
            else:
                data += struct.pack(">8I", self.magic, self.cputype, self.cpusubtype,
                                      self.filetype, self.ncmds, self.sizeofcmds, self.flags, self.reserved)
        else:
            if self.le:
                data += struct.pack("<7I", self.magic, self.cputype, self.cpusubtype,
                                      self.filetype, self.ncmds, self.sizeofcmds, self.flags)
            else:
                data += struct.pack(">7I", self.magic, self.cputype, self.cpusubtype,
                                      self.filetype, self.ncmds, self.sizeofcmds, self.flags)
        for cmd in self.cmds:
            data += cmd.dump()
        return data


class macho(object):
    def __init__(self, data, opt):
        self.data = data
        self.mh = mach_header(self.data)
        if 'inject' in opt and opt['inject']:
            if type(opt['inject']) == str:
                opt['inject'] = [opt['inject']]
            for dylib in opt['inject']:
                self.mh.add_header(dylib_command(1, dylib, True))
        if 'rminject' in opt and opt['rminject']:
            if type(opt['rminject']) == str:
                opt['rminject'] = [opt['rminject']]
            for dylib in opt['rminject']:
                for header in self.mh.cmds:
                    if header.cmd == LC_LOAD_DYLIB and header.path.strip('\0') == dylib:
                        self.mh.rm_header(header)
                        break

    def __len__(self):
        return len(self.data)

    def __str__(self):
        return self.mh.__str__()

    def dump(self):
        return self.mh.dump() + self.data[len(self.mh):]


def handle_macho(sign, opt, file):
    with open(file, 'rb') as f:
        bin_data = f.read()
    patch_ = True if 'inject' in opt or 'rminject' in opt else False
    print_ = True if 'print' in opt else False
    if opt['fat']:
        fh = fat_header(bin_data)
        machos = list()
        if print_:
            print(fh)
        for fa in fh.fat_archs:
            m = macho(bin_data[fa.offset:fa.offset+fa.size], opt)
            machos.append(m)
            if print_:
                print(m)
            if patch_:
                bin_data = bin_data[0:fa.offset] + \
                    m.dump() + bin_data[fa.offset+fa.size:]
    else:
        m = macho(bin_data, opt)
        if print_:
            print(m)
        if patch_:
            bin_data = m.dump()
    if patch_:
        patchfile = file + '.patch'
        with open(patchfile, 'wb') as f:
            f.write(bin_data)
        os.chmod(patchfile, os.stat(file).st_mode)
        print('successful patch to ' + patchfile)


def handle_help():
    print('Usage:  python bin_patch.py binary_path\n'
          '    --inject=library_path,library_path,...\n'
          '    --rminject=library_path\n'
          '    --print\n')


def handle_args(args):
    choice = {
        FAT_MAGIC: {
            'opt': {'fat': True, 'bit64': False},
            'handler': handle_macho
        },
        FAT_CIGAM: {
            'opt': {'fat': True, 'bit64': False},
            'handler': handle_macho
        },
        FAT_MAGIC_64: {
            'opt': {'fat': True, 'bit64': True},
            'handler': handle_macho
        },
        FAT_CIGAM_64: {
            'opt': {'fat': True, 'bit64': True},
            'handler': handle_macho
        },
        MH_MAGIC: {
            'opt': {'fat': False, 'bit64': False},
            'handler': handle_macho
        },
        MH_CIGAM: {
            'opt': {'fat': False, 'bit64': False},
            'handler': handle_macho
        },
        MH_MAGIC_64: {
            'opt': {'fat': False, 'bit64': True},
            'handler': handle_macho
        },
        MH_CIGAM_64: {
            'opt': {'fat': False, 'bit64': True},
            'handler': handle_macho
        }
    }
    if len(args) < 1:
        handle_help()
        return
    binary_path = args[0]
    if not os.path.exists(binary_path):
        print('%s not exist', binary_path)
        return
    opt = dict()
    for arg in args[1:]:
        if arg.find('=') != -1:
            k, v = tuple(arg.split('='))
            k = k.replace('-', '')
            if v.find(',') != -1:
                v = v.split(',')
            opt[k] = v
        else:
            opt[arg] = True
    with open(binary_path, 'rb') as f:
        sign, = struct.unpack('<I', f.read(4))
    if sign not in choice:
        print('cannot handle file sign 0x%08x' % sign)
    else:
        choose = choice[sign]
        opt.update(choose['opt'])
        choose['handler'](sign, opt, binary_path)
    return


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append('/tmp/AWZ')
    if len(sys.argv) == 2:
        # sys.argv.append('--print')
        sys.argv.append('--inject=/usr/lib/libtest.dylib,/usr/lib/libtest1.dylib')
    handle_args(sys.argv[1:])

