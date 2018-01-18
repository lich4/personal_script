#!/usr/bin/python2.6
# -*- coding: utf-8 -*-

import struct, sys, os



LC_SEGMENT = 1
LC_SYM_TAB = 2
LC_DY_SYM_TAB = 11
LC_DYLD_INFO_ONLY = 0x22 | 0x80000000
LC_DATA_IN_CODE = 0x29

def isSegmentCommand(command):
    return command.cmd == LC_SEGMENT

def isDyldInfoOnlyCommand(command):
    return command.cmd == LC_DYLD_INFO_ONLY

def isSymTabCommand(command):
    return command.cmd == LC_SYM_TAB

def isDySymTabCommand(command):
    return command.cmd == LC_DY_SYM_TAB

def isDataInCodeCommand(command):
    return command.cmd == LC_DATA_IN_CODE

class Section(object):
    descript = '16s16s9I'
    strusize = 68
    sectname = ''
    segname = ''
    addr = 0
    size = 0
    offset = 0
    align = 0
    reloff = 0
    nreloc = 0
    flags = 0
    reserved1 = 0
    reserved2 = 0
    data = None
    fatherSegment = None

    #for modification
    oldoffset = 0

    def __init__(self): # for user construct
        pass

    def __init__(self, data, seg):
        self.data = data
        self.sectname, self.segname, self.addr, self.size, self.offset, self.align, self.reloff, \
            self.nreloc, self.flags, self.reserved1, self.reserved2, = struct.unpack(self.descript, data[0:self.strusize])
        self.fatherSegment = seg

    def updateHeader(self):
        self.data = struct.pack(self.descript, self.sectname, self.segname, self.addr, self.size, \
            self.offset, self.align, self.reloff, self.nreloc, self.flags, self.reserved1, self.reserved2)
        return self.data

    def getZippedSecData(self, fp):
        fp.seek(self.oldoffset)
        return fp.read(self.size)

    def getSecData(self, fp):
        fp.seek(self.offset)
        return fp.read(self.size)

class LoadCommand(object):
    descript = '2I'
    strusize = 8
    cmd = 0
    cmdsize = 0
    data = None
    FatherMacho = None

    def __init__(self, data, macho):
        self.data = data
        self.cmd, self.cmdsize, = struct.unpack(self.descript, data[0:self.strusize])
        self.FatherMacho = macho

    def updateHeader(self):
        self.data = struct.pack(self.descript, self.cmd, self.cmdsize) + self.data[self.strusize:]
        return self.data

class SegmentCommand(LoadCommand):
    descript = '2I16s8I'
    strusize = 56
    cmd = 0
    cmdsize = 0
    segname = ''
    vmaddr = 0
    vmsize = 0
    fileoff = 0
    filesize = 0
    maxprot = 0
    initprot = 0
    nsects = 0
    flags = 0
    sections = None
    data = None
    segData = None # like __LINKEDIT

    # for modification
    oldfileoff = 0

    def __init__(self, data, macho):
        self.data = data
        self.cmd, self.cmdsize, self.segname, self.vmaddr, self.vmsize, self.fileoff, self.filesize,\
            self.maxprot, self.initprot, self.nsects, self.falgs, = struct.unpack(self.descript, data[0:self.strusize])

        if self.nsects != 0:
            self.sections = []
        for i in range(0, self.nsects):
            self.sections.append(Section(data[self.strusize+i*Section.strusize:self.strusize+(i+1)*Section.strusize], self))
        self.FatherMacho = macho

        if self.segname.strip('\0') == '__LINKEDIT':
            self.segData = True

    def updateHeader(self):
        self.data = struct.pack(self.descript, self.cmd, self.cmdsize, self.segname, self.vmaddr, \
            self.vmsize, self.fileoff, self.filesize, self.maxprot, self.initprot, self.nsects, self.flags)
        if self.sections is not None:
            for section in self.sections:
                self.data = self.data + section.updateHeader()
        return self.data

    def getZippedSecData(self, fp):
        fp.seek(self.oldfileoff)
        return fp.read(self.filesize)

    def getSecData(self, fp):
        fp.seek(self.fileoff)
        return fp.read(self.filesize)

class DyldInfoOnlyCommand(LoadCommand):
    descript = '12I'
    strusize = 48
    cmd = 0
    cmdsize = 0
    rebaseoff = 0 # need update
    rebasesize = 0 # need update
    bindoff = 0
    bindsize = 0
    weakbindoff = 0
    weakbindsize = 0
    lazybindoff = 0
    lazybindsize = 0
    exportoff = 0
    exportsize = 0
    data = None


    def __init__(self, data, macho):
        self.data = data
        self.cmd, self.cmdsize, self.rebaseoff, self.rebasesize, self.bindoff, self.bindsize,\
        self.weakbindoff, self.weakbindsize, self.lazybindoff, self.lazybindsize, self.exportoff,\
        self.exportsize, = struct.unpack(self.descript, data[0:self.strusize])

    def updateHeader(self):
        self.data = struct.pack(self.descript, self.cmd, self.cmdsize, self.rebaseoff, self.rebasesize,\
            self.bindoff, self.bindsize, self.weakbindoff, self.weakbindsize, self.lazybindoff, \
            self.lazybindsize, self.exportoff, self.exportsize)
        return self.data


class SymTabCommand(LoadCommand):
    descript = '6I'
    strusize = 24
    cmd = 0
    cmdsize = 0
    symtableoff = 0
    symtablecount = 0
    strtableoff = 0
    strtablesize = 0
    data = None

    def __init__(self, data, macho):
        self.data = data
        self.cmd, self.cmdsize, self.symtableoff, self.symtablecount, self.strtableoff, \
            self.strtablesize, = struct.unpack(self.descript, data[0:self.strusize])

    def updateHeader(self):
        self.data = struct.pack(self.descript, self.cmd, self.cmdsize, self.symtableoff, \
            self.symtablecount, self.strtableoff, self.strtablesize)
        return self.data

class DySymTabCommand(LoadCommand):
    descript = '20I'
    strusize = 80
    cmd = 0
    cmdsize = 0
    indexlocalsym = 0
    localsymsize = 0
    indexextsym = 0
    extdefsymsize = 0
    indexundefsym = 0
    undefsymsize = 0
    tablecontentoff = 0
    entriestocsize = 0
    fileoffmodtable = 0
    modtableentrysize = 0
    extrefsymtableoff = 0
    extrefsymtablesize = 0
    indsymtableoff = 0
    indsymtablesize = 0
    extrelocentryoff = 0
    extrelocentrysize = 0
    localrelocentryoff = 0
    localrelocentrysize = 0
    data = None

    def __init__(self, data, macho):
        self.data = data
        self.cmd, self.cmdsize, self.indexlocalsym, self.localsymsize, self.indexextsym, \
            self.extdefsymsize, self.indexundefsym, self.undefsymsize, self.tablecontentoff, \
            self.entriestocsize, self.fileoffmodtable, self.modtableentrysize, self.extrefsymtableoff, \
            self.extrefsymtablesize, self.indsymtableoff, self.indsymtablesize, self.extrelocentryoff, \
            self.extrelocentrysize, self.localrelocentryoff, self.localrelocentrysize \
                = struct.unpack(self.descript, data[0:self.strusize])

    def updateHeader(self):
        self.data = struct.pack(self.descript, self.cmd, self.cmdsize, self.indexlocalsym, \
            self.localsymsize, self.indexextsym, self.extdefsymsize, self.indexundefsym, \
            self.undefsymsize, self.tablecontentoff, self.entriestocsize, self.fileoffmodtable, \
            self.modtableentrysize, self.extrefsymtableoff, self.extrefsymtablesize, self.indsymtableoff,\
            self.indsymtablesize, self.extrelocentryoff, self.extrelocentrysize, self.localrelocentryoff,
            self.localrelocentrysize)
        return self.data


class DataInCodeCommand(LoadCommand):
    descript = '4I'
    strusize = 16
    cmd = 0
    cmdsize = 0
    dataoff = 0
    datasize = 0
    data = None

    def __init__(self, data, macho):
        self.data = data
        self.cmd, self.cmdsize, self.dataoff, self.datasize, = struct.unpack(self.descript, data[0:self.strusize])

    def updateHeader(self):
        self.data = struct.pack(self.descript, self.cmd, self.cmdsize, self.dataoff, self.datasize)
        return self.data

class MachoHeader(object):
    descript = '7I'
    strusize = 28
    magic = 0
    cpu_type = 0
    cpu_sub_type = 0
    file_type = 0
    num_load_comands = 0
    size_of_load_commands = 0
    flags = 0
    data = None

    def __init__(self, data):
        self.data = data
        self.magic, self.cpu_type, self.cpu_sub_type, self.file_type, self.num_load_comands,\
            self.size_of_load_commands, self.flags, = struct.unpack(self.descript, data[0:self.strusize])

    def updateHeader(self):
        self.data = struct.pack(self.descript, self.magic, self.cpu_type, self.cpu_sub_type,
            self.file_type, self.num_load_comands, self.size_of_load_commands, self.flags)
        return self.data

class MachoFile(object):
    header = None
    loadCommands = None
    sections = None

    def __init__(self, fp):
        curPos = fp.tell()
        self.header = MachoHeader(fp.read(MachoHeader.strusize))
        if self.header.magic != 0xFEEDFACE:
            raise 'Invalid macho file'
        curPos = curPos + MachoHeader.strusize
        self.loadCommands = []
        self.sections = []
        for i in range(0, self.header.num_load_comands):
            command = LoadCommand(fp.read(LoadCommand.strusize), self)
            fp.seek(curPos)
            if isSegmentCommand(command): # SEGMENT
                command = SegmentCommand(fp.read(command.cmdsize), self)
                if command.sections is not None:
                    for section in command.sections:
                        self.sections.append(section)
            elif isDyldInfoOnlyCommand(command): # DYLD_INFO_ONLY
                command = DyldInfoOnlyCommand(fp.read(command.cmdsize), self)
            elif isSymTabCommand(command): # SYM_TAB
                command = SymTabCommand(fp.read(command.cmdsize), self)
            elif isDySymTabCommand(command): # DY_SYM_TAB
                command = DySymTabCommand(fp.read(command.cmdsize), self)
            elif isDataInCodeCommand(command): # DATA_IN_CODE
                command = DataInCodeCommand(fp.read(command.cmdsize), self)
            else:
                command = LoadCommand(fp.read(command.cmdsize), self)
            curPos = curPos + command.cmdsize
            self.loadCommands.append(command)

    '''
        Insert Section object into SegmentCommand
    '''
    def addSectionForSegment(self, section, segment):
        # check if repeat
        if segment is not None:
            if segment.sections is None:
                return
            for section in segment.sections:
                if section.addr == section.addr:
                    return

        self.sections.append(section)
        if segment.sections is None:
            segment.sections = []
        segment.sections.append(section)
        segment.cmdsize = segment.cmdsize + section.strusize
        segment.nsects = segment.nsects + 1
        self.header.size_of_load_commands = self.header.size_of_load_commands + section.strusize
        # update header

    '''
        Add Segment
    '''
    def addCommand(self, command):
        # check if repeat
        for lcommand in self.loadCommands:
            if isSegmentCommand(lcommand):
                segment = lcommand
                if segment.vmaddr == command.vmaddr:
                    return

        self.loadCommands.append(command)
        self.header.num_load_comands = self.header.num_load_comands + 1
        self.header.size_of_load_commands = self.header.size_of_load_commands + command.cmdsize
        if isSegmentCommand(command) and command.sections is not None:
            segment = command
            if self.sections is None:
                self.sections = []
            for section in segment.sections:
                self.sections.append(section)

    '''
        Squeeze space
    '''
    def zipData(self):
        off = self.header.strusize
        linkeditSeg = None
        for command in self.loadCommands:
            off = off + command.cmdsize
        for command in self.loadCommands:
            if isSegmentCommand(command):
                segment = command
                off = off + 0x1000 - (off & 0xFFF)  # align
                segment.oldfileoff = segment.fileoff
                segment.fileoff = off
                if segment.sections is not None:
                    for section in segment.sections:
                        section.oldoffset = section.offset
                        section.offset = section.addr - segment.vmaddr + segment.fileoff
                        off = section.offset
                if segment.segData is not None:
                    off = off + segment.filesize
                if segment.segname.strip('\0') == '__LINKEDIT':
                    linkeditSeg = segment
            elif isDyldInfoOnlyCommand(command):
                dyldinfo = command
                if dyldinfo.rebaseoff != 0:
                    dyldinfo.rebaseoff = dyldinfo.rebaseoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dyldinfo.bindoff != 0:
                    dyldinfo.bindoff = dyldinfo.bindoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dyldinfo.weakbindoff != 0:
                    dyldinfo.weakbindoff = dyldinfo.weakbindoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dyldinfo.lazybindoff != 0:
                    dyldinfo.lazybindoff = dyldinfo.lazybindoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dyldinfo.exportoff != 0:
                    dyldinfo.exportoff = dyldinfo.exportoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                off = off + command.cmdsize
            elif isSymTabCommand(command):
                symtab = command
                if symtab.symtableoff != 0:
                    symtab.symtableoff = symtab.symtableoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if symtab.strtableoff != 0:
                    symtab.strtableoff = symtab.strtableoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
            elif isDySymTabCommand(command):
                dsymtab = command
                if dsymtab.tablecontentoff != 0:
                    dsymtab.tablecontentoff = dsymtab.tablecontentoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dsymtab.fileoffmodtable != 0:
                    dsymtab.fileoffmodtable = dsymtab.fileoffmodtable - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dsymtab.extrefsymtableoff != 0:
                    dsymtab.extrefsymtableoff = dsymtab.extrefsymtableoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dsymtab.indsymtableoff != 0:
                    dsymtab.indsymtableoff = dsymtab.indsymtableoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dsymtab.extrelocentryoff != 0:
                    dsymtab.extrelocentryoff = dsymtab.extrelocentryoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
                if dsymtab.localrelocentryoff != 0:
                    dsymtab.localrelocentryoff = dsymtab.localrelocentryoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff
            elif isDataInCodeCommand(command):
                dataincode = command
                if dataincode.dataoff != 0:
                    dataincode.dataoff = dataincode.dataoff - linkeditSeg.oldfileoff + linkeditSeg.fileoff

    '''
        Write to new file
    '''
    def updateData(self, oldfp, newfp):
        # reconstruct sections
        newfp.write(self.header.updateHeader())
        for command in self.loadCommands:
            newfp.write(command.updateHeader())
        for command in self.loadCommands:
            if isSegmentCommand(command):
                segment = command
                if segment.sections is not None:
                    for section in segment.sections:
                        newfp.seek(section.offset)
                        newfp.write(section.getZippedSecData(oldfp))
                if segment.segData is not None:
                    newfp.seek(segment.fileoff)
                    newfp.write(segment.getZippedSecData(oldfp))

class dyldCacheHeader(object):
    descript = '16s4I7Q'
    strusize = 0x58
    magic = ''
    mappingOffset = 0
    mappingCount = 0
    imagesOffset = 0
    imagesCount = 0
    dyldBaseAddress = 0
    codeSignatureOffset = 0
    codeSignatureSize = 0
    slideInfoOffset = 0
    slideInfoSize = 0
    localSymbolsOffset = 0
    localSymbolsSize = 0

    def __init__(self, data):
        self.magic, self.mappingOffset, self.mappingCount, self.imagesOffset, self.imagesCount,\
            self.dyldBaseAddress, self.codeSignatureOffset, self.codeSignatureSize, \
            self.slideInfoOffset, self.slideInfoSize, self.localSymbolsOffset, \
            self.localSymbolsSize = struct.unpack(self.descript, data[0:self.strusize])


class dyldCacheMapping(object):
    descript = '3Q2I'
    strusize = 0x20
    address = 0
    size = 0
    fileOffset = 0
    maxProt = 0
    initProt = 0

    filename = ''

    def __init__(self, data):
        self.address, self.size, self.fileOffset, self.maxProt, self.initProt = \
            struct.unpack(self.descript, data[0:self.strusize])


class dyldCacheImage(object):
    descript = '3Q2I'
    strusize = 0x20
    address = 0
    modTime = 0
    inode = 0
    pathFileOffset = 0
    pad = 0

    filename= ''

    def __init__(self, data, fp):
        self.address, self.modTime, self.inode, self.pathFileOffset, self.pad = \
            struct.unpack(self.descript, data[0:self.strusize])
        beginPos = fp.tell()
        fp.seek(self.pathFileOffset)
        self.filename = fp.read(0x100).split('\0')[0]
        fp.seek(beginPos)

class dyldCache(object):
    header = None
    cacheMapping = []
    cacheImage = []

    def __init__(self, fp):
        fp.seek(0)
        self.header = dyldCacheHeader(fp.read(dyldCacheHeader.strusize))
        fp.seek(self.header.mappingOffset)
        for i in range(0, self.header.mappingCount):
            self.cacheMapping.append(dyldCacheMapping(fp.read(dyldCacheMapping.strusize)))
        fp.seek(self.header.imagesOffset)
        for i in range(0, self.header.imagesCount):
            self.cacheImage.append(dyldCacheImage(fp.read(dyldCacheImage.strusize), fp))

    def getFileOffsetFromMemOffset(self, address):
        for item in self.cacheMapping:
            if address >= item.address and address < item.address + item.size:
                return address - item.address + item.fileOffset
        return -1


    def parseMacho(self, fp):
        macho = {}
        for item in self.cacheImage:
            fileoff = self.getFileOffsetFromMemOffset(item.address)
            if fileoff == -1:
                continue
            fp.seek(fileoff)
            macho[item.address] = {'name':item.filename, 'macho':MachoFile(fp)}
        return macho

if __name__ == '__main__':
    cachepath = ''
    op = ''
    toextract = ''
    for arg in sys.argv:
        if arg.find('-cachepath=') != -1:
            cachepath = arg.replace('-cachepath=', '')
        elif arg.find('-listlib') != -1:
            op = 'listlib'
        elif arg.find('-listsel') != -1:
            op = 'listsel'
        elif arg.find('-listsec') != -1:
            op = 'listsec'
        elif arg.find('-extract=') != -1:
            op = 'extract'
            toextract = arg.replace('-extract=', '')
        elif arg.find('-help') != -1:
            print '-cachepath=/path/to/dyld_shared_cache\t\t\t\tSpedify image to parse'
            print '-listlib\t\t\t\tShow library name'
            print '-listsel\t\t\t\tShow selector'
            print '-listsec\t\t\t\tShow section'
            print '-extract=UIKit\t\t\t\tExtract single image'
            sys.exit()

    if cachepath == '' or op == '':
        sys.exit()

    fp = open(cachepath,'rb')
    cache = dyldCache(fp)
    machos = cache.parseMacho(fp)

    if op == 'listlib':
        for addr in sorted(machos):
            print '%08x:%s' % (addr, machos[addr]['name'])
        '''
        Output like:
        20028000:/System/Library/AccessibilityBundles/AXSpeechImplementation.bundle/AXSpeechImplementation
        2002d000:/System/Library/AccessibilityBundles/AccessibilitySettingsLoader.bundle/AccessibilitySettingsLoader
        2c659000:/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager
        20190000:/System/Library/AccessibilityBundles/WebProcessLoader.axbundle/WebProcessLoader
        32bba000:/usr/lib/libETLDMCDynamic.dylib
        2e31b000:/System/Library/PrivateFrameworks/ProxiedCrashCopierClient.framework/ProxiedCrashCopierClient
        324dd000:/System/Library/WeeAppPlugins/AttributionWeeApp.bundle/AttributionWeeApp
        '''

    elif op == 'listsel':
        selectorTable = {} # objc selector 地址映射表，用于修复objc_selref段
        for addr in machos:
            methnameSec = None
            for section in machos[addr]['macho'].sections:
                if section.sectname.find('__objc_methname') != -1:
                    methnameSec = section
                    break
            if methnameSec is not None:
                off = 0
                for curstr in methnameSec.getSecData(fp).split('\0'):
                    selectorTable[section.addr + off] = curstr
                    off = off + len(curstr)
        for addr in sorted(selectorTable.keys()):
            print '%08x:%s' % (addr, selectorTable[addr])
        '''
        Output like:
        33ddeac8:sharedPreferencesController
        33ddeae3:loggingLevel
        33ddeaef:initWithMachServiceName:options:
        33ddeb0f:isUpdateWaitingWithReply:
        33ddeb28:purgeAllAssetsWithReply:
        33ddeb40:interfaceWithProtocol:
        33ddeb56:setRemoteObjectInterface:
        33ddeb6f:resume
        33ddeb75:createNewXPCConnection
        '''

    elif op == 'listsec':
        sectionTable = {}
        for addr in machos:
            for section in machos[addr]['macho'].sections:
                sectionTable[section.addr] = section
        for addr in sorted(sectionTable.keys()):
            print '%08x-%08x+%08x:%s' % (addr, addr + sectionTable[addr].size, sectionTable[addr].offset, sectionTable[addr].sectname)
        '''
        Output like:
        200293c8-2002bde0+000293c8:__text
        2002bde0-2002bef0+0002bde0:__picsymbolstub4
        2002bef0-2002bfe0+0002bef0:__stub_helper
        2002bfe0-2002c2e4+0002bfe0:__cstring
        2002c2e4-2002cef1+0002c2e4:__objc_methname
        2002cef1-2002cf73+0002cef1:__objc_classname
        2002cf73-2002cffa+0002cf73:__objc_methtype
        2002e1c8-20032660+0002e1c8:__text
        20032660-20032a20+00032660:__picsymbolstub4
        '''

    elif op == 'extract':
        sectionTable = {}
        targetMacho = None
        for addr in machos:
            methnameSec = None
            for section in machos[addr]['macho'].sections:
                sectionTable[section.addr] = section
            if machos[addr]['name'].find(toextract) != -1:
                targetMacho = machos[addr]
        if targetMacho is None:
            print 'Target not exist'
            sys.exit()

        # begin fix selector
        for section in targetMacho['macho'].sections:
            sectname = section.sectname.strip('\0')
            if sectname in ['__objc_selrefs', '__objc_catlist', '__objc_classlist']:
                # read address
                off = 0
                while off < section.size:
                    selnameVMOff, = struct.unpack('I', section.getSecData(fp)[off:off + 4])
                    for saddr in sorted(sectionTable.keys(), reverse=True):
                        if saddr < selnameVMOff:
                            # todo 更好的处理
                            targetMacho['macho'].addCommand(sectionTable[saddr].fatherSegment)
                            break
                    off = off + 4

        targetMacho['macho'].zipData()
        newFp = open(os.path.basename(targetMacho['name']), 'wb')
        targetMacho['macho'].updateData(fp, newFp)
        newFp.close()
        fp.close()

