// https://codeshare.frida.re/@lichao890427/find-android-hook/
// Any questions submit to https://github.com/lichao890427/frida_script 

// Usage:
/*
	// Get All Modules from /proc/self/maps
	[Xiaomi MI 4LTE::com.b.wallet]-> getAllModules()
	{
        "path": "/data/app-lib/com.b.wallet-1/libbdpush_V2_7.so",
        "vmmax": "2140905472",
        "vmmin": "2140844032"
    },
    {
        "path": "/data/data/com.b.wallet/files/.1/dex/apkDex/1-2.4.5.dex",
        "vmmax": "2161364992",
        "vmmin": "2160836608"
    },
    {
        "path": "/data/local/tmp/re.frida.server/frida-agent-32.so",
        "vmmax": "2172952576",
        "vmmin": "2161606656"
    },
    {
        "path": "/data/data/com.b.wallet/files/.100015/dex/apkDex/100015-1.0.0.dex",
        "vmmax": "2189901824",
        "vmmin": "2189869056"
    }
	...................


	// Check got table hook
	[Xiaomi MI 4LTE::com.b.wallet]-> checkConsistency("libdvm.so", 4)
	check .got
	.got 39/349     addr:41764b28 file-mem:0-40109708 __aeabi_idiv->libc.so.__divsi3
	.got 44/349     addr:41764b3c file-mem:0-4010a2ec __aeabi_fadd->libc.so.__addsf3
	.got 45/349     addr:41764b40 file-mem:0-4010a2e8 __aeabi_fsub->libc.so.__aeabi_frsub
	.got 50/349     addr:41764b54 file-mem:0-40109864 __aeabi_dadd->libc.so.__adddf3
	.got 115/349    addr:41764c58 file-mem:1f738-40109708 __aeabi_idiv->libc.so.__divsi3
	.got 129/349    addr:41764c90 file-mem:1f738-4010a134 __aeabi_cdcmple->libc.so.__aeabi_cdcmpeq
	.got 130/349    addr:41764c94 file-mem:1f738-401521e0 __aeabi_cfcmple->libm.so.__aeabi_cfrcmple
	.got 136/349    addr:41764cac file-mem:1f738-7549c681 __android_log_print->libbprotect.so.unknown
	.got 138/349    addr:41764cb4 file-mem:1f738-4013a919 _Znaj->libstdc++.so._Znwj
	.got 139/349    addr:41764cb8 file-mem:1f738-4013a927 _ZdaPv->libstdc++.so._ZdlPv
	.got 161/349    addr:41764d10 file-mem:1f738-402d461b _ZSt24__stl_throw_length_errorPKc->libstlport.so._ZSt25__stl_throw_runtime_errorPKc
	.got 190/349    addr:41764d84 file-mem:1f738-40109640 __aeabi_uidiv->libc.so.__udivsi3
	.got 228/349    addr:41764e1c file-mem:1f738-7549c691 read->libbprotect.so.unknown
	.got 230/349    addr:41764e24 file-mem:1f738-71c17101 dlsym->libsechook.so._ZNK7android12SortedVectorIP6soinfoE8do_splatEPvPKvj
	.got 231/349    addr:41764e28 file-mem:1f738-71c17421 dlopen->libsechook.so._ZNK7android12SortedVectorIP6soinfoE10do_compareEPKvS5_
	.got 232/349    addr:41764e2c file-mem:1f738-400b4dad dlerror->linker._start
	.got 292/349    addr:41764f1c file-mem:1f738-71c16f05 socket->libsechook.so.__socket
	.got 334/349    addr:41764fc4 file-mem:1f738-4176ee11 _ZN4MaAcC1EiPKtib->libqc-opt.so._ZN4MaAcC2EiPKtib
	.got 338/349    addr:41764fd4 file-mem:1f738-4176ee61 _ZN4MaAcD1Ev->libqc-opt.so._ZN4MaAcD2Ev
	
	// Check inline hook
	[Xiaomi MI 4LTE::com.b.wallet]-> checkConsistency("libdvm.so", 2)
	check .text
	.text   addr:_Z17dvmDbgIsInterfacey+7 file-mem:14-df
	may be hook
	.text   addr:_Z18dvmDbgGetClassListPjPPy+0 file-mem:4b-f8
	may be hook
	.text   addr:_Z18dvmDbgGetClassListPjPPy+1 file-mem:15-0
	may be hook
	.text   addr:_Z18dvmDbgGetClassListPjPPy+2 file-mem:4a-f0
	may be hook
	.text   addr:_Z18dvmDbgGetClassListPjPPy+3 file-mem:7b-1
	may be hook
	.text   addr:_Z18dvmDbgGetClassListPjPPy+4 file-mem:44-73
	may be hook
	.text   addr:_Z18dvmDbgGetClassListPjPPy+5 file-mem:73-7f
	may be hook
	.text   addr:_Z18dvmDbgGetClassListPjPPy+6 file-mem:b5-7f
	may be hook
	
	// Dump elf
	[Xiaomi MI 4LTE::com.b.wallet]-> dumpModule("libbprotect.so")
	write /sdcard/libbprotect.so file->mem 2bf0->75492bf0 size:45e98
*/


var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_APPEND = 1024;
var O_LARGEFILE = 32768;
var O_CREAT = 64;
var S_IWUSR = 128;
var S_IRWXU = 448;
var S_IRUSR = 256;
var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function getStr(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readUtf8String(addr);
}

function getStrSize(addr, size) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readUtf8String(addr, size);
}

function putStr(addr, str) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeUtf8String(addr, str);
}

function getByteArr(addr, l) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readByteArray(addr, l);
}

function getU8(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU8(addr);
}

function putU8(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU8(addr, n);
}

function getU16(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU16(addr);
}

function putU16(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU16(addr, n);
}

function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU32(addr);
}

function putU32(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU32(addr, n);
}

function getU64(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU64(addr);
}

function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU64(addr, n);
}

function getPt(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readPointer(addr);
}

function putPt(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    if (typeof n == "number") {
        n = ptr(n);
    }
    return Memory.writePointer(addr, n);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

function dumpMemory(addr, length) {
    console.log(hexdump(Memory.readByteArray(addr, length), {
        offset: 0,
        length: length,
        header: true,
        ansi: true
    }));
}

wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
lseek = getExportFunction("f", "lseek", "int", ["int", "int", "int"]);
wrapper_errno = getExportFunction("f", "__errno", "pointer", []);
close = getExportFunction("f", "close", "int", ["int"]);
dladdr = getExportFunction("f", "dladdr", "int", ["pointer", "pointer"]);
wrapper_sscanf = getExportFunction("f", "sscanf", "int", ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "pointer"]);
getpid = getExportFunction("f", "getpid", "int", []);
wrapper_popen = getExportFunction("f", "popen", "pointer", ["pointer", "pointer"]);
pclose = getExportFunction("f", "pclose", "int", ["pointer"]);
fgets = getExportFunction("f", "fgets", "pointer", ["pointer", "int", "pointer"]);
sleep = getExportFunction("f", "sleep", "int", ["int"]);

function errno() {
	return getU32(wrapper_errno());
}

function popen(command, type) {
    if (typeof command == "string") {
        command = allocStr(command);
    }
    if (typeof type == "string") {
        type = allocStr(type);
    }
    return wrapper_popen(command, type);
}

function getCommandOutput(cmd) {
    var fp = popen(cmd, "r");
    if (fp.isNull()) {
        return null;
    }
    var output = "";
    var buffer = malloc(1024);
    while (fgets(buffer, 1024, fp) > 0) {
        output += getStr(buffer);
    }
    pclose(fp);
    return output;
}

function getProcessName() {
    var fd = open("/proc/" + getpid() + "/cmdline", O_RDONLY, 0);
    if (fd == -1) {
        return "unknown";
    }
    var buffer = malloc(32);
    read(fd, buffer, 32);
    close(fd);
    return getStr(buffer);
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

function getFileSize(fd) {
    return lseek(fd, 0, SEEK_END);
}

function malloc(size) {
    return Memory.alloc(size);
}

function memcpy(dst, src, n) {
    return Memory.copy(dst, src, n);
}

function sscanf(buffer, format, np1, np2, np3, np4, np5, np6, np7, np8, np9, np10, np11) {
    if (typeof format == "string") {
        format = allocStr(format);
    }
    return wrapper_sscanf(buffer, format, np1, np2, np3, np4, np5, np6, np7, np8, np9, np10, np11);
}

function getSymbol(addr) {
    if (addr == 0) {
        return new Object();
    }
    var dlinfo = malloc(32);
    var npaddr = ptr(addr);
    putU64(dlinfo.add(0), 0);
    putU64(dlinfo.add(8), 0);
    putU64(dlinfo.add(16), 0);
    putU64(dlinfo.add(24), 0);
    dladdr(npaddr, dlinfo);
    var sym = new Object();
    if (Process.pointerSize == 4) {
        libnameptr = getPt(dlinfo.add(0));
        if (libnameptr.isNull()) {
            sym.libname = "unknown";
        } else {
            sym.libname = getStr(libnameptr);
        }
        funcnameptr = getPt(dlinfo.add(8));
        if (funcnameptr.isNull()) {
            sym.funcname = "unknown";
        } else {
            sym.funcname = getStr(funcnameptr);
        }
        sym.libbase = getU32(dlinfo.add(4));
        sym.funcoff = npaddr.sub(getPt(dlinfo.add(12)));
    } else {
        libnameptr = getPt(dlinfo.add(0));
        if (libnameptr.isNull()) {
            sym.libname = "unknown";
        } else {
            sym.libname = getStr(libnameptr);
        }
        funcnameptr = getPt(dlinfo.add(16));
        if (funcnameptr.isNull()) {
            sym.funcname = "unknown";
        } else {
            sym.funcname = getStr(funcnameptr);
        }
        sym.libbase = getU64(dlinfo.add(8));
        sym.funcoff = npaddr.sub(getPt(dlinfo.add(24)));
    }
    if (sym.libname == "unknown" || sym.funcname == "unknown") {
        for (var i = global_symbols.length - 1; i >= 0; i--) {
            if (addr >= global_symbols[i].address) {
                sym.libname = global_symbols[i].path;
                sym.funcname = global_symbols[i].name;
                sym.funcoff = addr - global_symbols[i].address;
                break;
            }
        }
    }
    return sym;
}

function readSmallFile(filepath) {
    var fd = open(filepath, O_RDONLY, 0);
    if (fd == -1) {
        return null;
    }
    var buffersize = 0x1000;
    var buffer = malloc(buffersize);
    lseek(fd, 0, SEEK_SET);
    var output = "";
    while (read(fd, buffer, buffersize) != 0) {
        output += getStr(buffer);
    }
    close(fd);
    return output;
}

function getAllModules() { // Some modules may hide themselves in 'solist', so we use maps instead
    var modulelines = readSmallFile("/proc/self/maps").split("\n");
    var modules = new Array();
    var buffer = malloc(512);
    for (var i = 0; i < modulelines.length; i++) {
        putStr(buffer.add(256), modulelines[i]);
        putU64(buffer.add(0), 0); // begin address
        putU64(buffer.add(8), 0); // end address
        putU64(buffer.add(16), 0); // permission
        putU64(buffer.add(24), 0); // pgoff
        putU64(buffer.add(32), 0); // major
        putU64(buffer.add(40), 0); // minor
        putU64(buffer.add(48), 0); // ino
        putU64(buffer.add(56), 0); // path
        sscanf(buffer.add(256), "%lx-%lx %c%c%c%c %llx %x:%x %lu %s", buffer.add(0), buffer.add(8), buffer.add(16), buffer.add(17), buffer.add(18), buffer.add(19), buffer.add(24), buffer.add(32), buffer.add(40), buffer.add(48), buffer.add(56));
        var vmmin = getU64(buffer.add(0));
        var vmmax = getU64(buffer.add(8));
        var path = getStr(buffer.add(56));
		var perm = getStr(buffer.add(16));
        if (path[0] != "/") {
            continue;
        }
        // Check exist
        var exist = false;
        for (var j = 0; j < modules.length; j++) {
            if (modules[j].path == path) {
                if (modules[j].vmmin > vmmin) {
                    modules[j].vmmin = vmmin;
                }
                if (modules[j].vmmax < vmmax) {
                    modules[j].vmmax = vmmax;
                }
                exist = true;
                break;
            }
        }
        if (!exist) {
            var module = new Object();
            module.vmmin = vmmin;
            module.vmmax = vmmax;
            module.path = path;
            modules.push(module);
        }
    }
    return modules;
}

// Export function: get all loaded module info
function checkAllModules() {
	if (modules == null) {
		modules = getAllModules();
	}
    for (var i = 0; i < modules.length; i++) {
        console.log("start:" + modules[i].vmmin.toString(16) + " end:" + modules[i].vmmax.toString(16) + " path:" + modules[i].path);
    }
}

function getModuleInfo(name) {
	if (modules == null) {
		modules = getAllModules();
	}
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            console.log(i + " start:" + modules[i].vmmin.toString(16) + " end:" + modules[i].vmmax.toString(16) + 
				" path:" + modules[i].path + " size:" + (modules[i].vmmax - modules[i].vmmin).toString(16));
        }
    }
}

function getElfData(module) {
    if ("sections" in module) {
        return true;
    }
    var fd = open(module.path, O_RDONLY, 0);
    if (fd == -1) {
        return false;
    }
    // Read elf header
    var size_of_Elf32_Ehdr = 52;
    var off_of_Elf32_Ehdr_phoff = 28; // 4
    var off_of_Elf32_Ehdr_shoff = 32; // 4
    var off_of_Elf32_Ehdr_phentsize = 42; // 2
    var off_of_Elf32_Ehdr_phnum = 44; // 2
    var off_of_Elf32_Ehdr_shentsize = 46; // 2
    var off_of_Elf32_Ehdr_shnum = 48; // 2
    var off_of_Elf32_Ehdr_shstrndx = 50; // 2
    var size_of_Elf64_Ehdr = 64;
    var off_of_Elf64_Ehdr_phoff = 32; // 8
    var off_of_Elf64_Ehdr_shoff = 40; // 8
    var off_of_Elf64_Ehdr_phentsize = 54; // 2
    var off_of_Elf64_Ehdr_phnum = 56; // 2
    var off_of_Elf64_Ehdr_shentsize = 58; // 2
    var off_of_Elf64_Ehdr_shnum = 60; // 2
    var off_of_Elf64_Ehdr_shstrndx = 62; // 2
    // Parse Ehdr
    var ehdr = malloc(64);
    lseek(fd, 0, SEEK_SET);
    read(fd, ehdr, 64);
    var is32bit = getU8(ehdr.add(4)) != 2; // 1:32 2:64
    if (is32bit) {
        var phoff = getU32(ehdr.add(off_of_Elf32_Ehdr_phoff));
        var shoff = getU32(ehdr.add(off_of_Elf32_Ehdr_shoff));
        var phentsize = getU16(ehdr.add(off_of_Elf32_Ehdr_phentsize));
        var phnum = getU16(ehdr.add(off_of_Elf32_Ehdr_phnum));
        var shentsize = getU16(ehdr.add(off_of_Elf32_Ehdr_shentsize));
        var shnum = getU16(ehdr.add(off_of_Elf32_Ehdr_shnum));
        var shstrndx = getU16(ehdr.add(off_of_Elf32_Ehdr_shstrndx));
        var off_of_Elf_Shdr_shname = 0; // 4
        var off_of_Elf_Shdr_shaddr = 12; // 4
        var off_of_Elf_Shdr_shoffset = 16; // 4
        var off_of_Elf_Shdr_shsize = 20; // 4
    } else {
        var phoff = getU64(ehdr.add(off_of_Elf64_Ehdr_phoff));
        var shoff = getU64(ehdr.add(off_of_Elf64_Ehdr_shoff));
        var phentsize = getU16(ehdr.add(off_of_Elf64_Ehdr_phentsize));
        var phnum = getU16(ehdr.add(off_of_Elf64_Ehdr_phnum));
        var shentsize = getU16(ehdr.add(off_of_Elf64_Ehdr_shentsize));
        var shnum = getU16(ehdr.add(off_of_Elf64_Ehdr_shnum));
        var shstrndx = getU16(ehdr.add(off_of_Elf64_Ehdr_shstrndx));
        var off_of_Elf_Shdr_shname = 0; // 4
        var off_of_Elf_Shdr_shaddr = 16; // 8
        var off_of_Elf_Shdr_shoffset = 24; // 8
        var off_of_Elf_Shdr_shsize = 28; // 8
    }
    // Parse Shdr
    var shdrs = malloc(shentsize * shnum);
    lseek(fd, shoff, SEEK_SET);
    read(fd, shdrs, shentsize * shnum);
    if (is32bit) {
        shstr_offset = getU32(shdrs.add(shentsize * shstrndx + off_of_Elf_Shdr_shoffset));
        shstr_size = getU32(shdrs.add(shentsize * shstrndx + off_of_Elf_Shdr_shsize));
    } else {
        shstr_offset = getU64(shdrs.add(shentsize * shstrndx + off_of_Elf_Shdr_shoffset));
        shstr_size = getU64(shdrs.add(shentsize * shstrndx + off_of_Elf_Shdr_shsize));
    }
    var str_tbl = malloc(shstr_size);
    lseek(fd, shstr_offset, SEEK_SET);
    read(fd, str_tbl, shstr_size);
    var sections = new Array();
    for (var i = 0; i < shnum; i++) {
        if (is32bit) {
            var shname_off = getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shname));
            var shname = getStr(str_tbl.add(shname_off));
            var shaddr = getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shaddr));
            var shoffset = getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shoffset));
            var shsize = getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shsize));
        } else {
            var shname_off = getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shname));
            var shname = getStr(str_tbl.add(shname_off));
            var shaddr = getU64(shdrs.add(i * shentsize + off_of_Elf_Shdr_shaddr));
            var shoffset = getU64(shdrs.add(i * shentsize + off_of_Elf_Shdr_shoffset));
            var shsize = getU64(shdrs.add(i * shentsize + off_of_Elf_Shdr_shsize));
        }
        if (shname == ".text" || shname == ".rodata" || shname == ".got" || shname == ".got.plt") {
            // Check item
            var section = new Object();
            section.name = shname;
            section.memaddr = shaddr + module.vmmin;
			section.memoff = shaddr;
			section.fileoff = shoffset;
            section.size = shsize;
            section.data = malloc(shsize);
            lseek(fd, shoffset, SEEK_SET);
            read(fd, section.data, shsize);
            sections.push(section);
        }
        if (shname == ".dynsym" || shname == ".dynstr" || shname == ".rel.dyn" || shname == ".rel.plt") {
            var section = new Object();
            section.size = shsize;
            section.memaddr = shaddr + module.vmmin;
			section.memoff = shaddr;
			section.fileoff = shoffset;
            module[shname] = section;
        }
    }
    if (Process.pointerSize == 4) {
        var sym_2_str = [];
        if ((".dynsym" in module) && (".dynstr" in module)) {
            for (var i = 0; i < module[".dynsym"].size / 16; i++) {
                sym_2_str.push(getStr(module[".dynstr"].memaddr + getU32(module[".dynsym"].memaddr + 16 * i)));
            }
        }
		module.sym_2_str = sym_2_str;
		var relmap = {};
        if (".rel.dyn" in module) {
			var shsize = module[".rel.dyn"].size;
			var memaddr = module[".rel.dyn"].memaddr;
			for (var j = 0; j < shsize / 8; j++) {
				var key = getU32(memaddr + j * 8);
				var val = getU32(memaddr + j * 8 + 4) >> 8;
				if (key != 0 && val != 0) {
					relmap[key] = val;
				}
			}
        }
		if (".rel.plt" in module) {
			var shsize = module[".rel.plt"].size;
			var memaddr = module[".rel.plt"].memaddr;
			for (var j = 0; j < shsize / 8; j++) {
				var key = getU32(memaddr + j * 8);
				var val = getU32(memaddr + j * 8 + 4) >> 8;
				if (key != 0 && val != 0) {
					relmap[key] = val;
				}
			}
		}
		module.dyn_2_name = relmap;
    }
    module.sections = sections;
    return true;
}

function compareMemory(module, mask) {
    for (var i = 0; i < module.sections.length; i++) {
        section = module.sections[i];
        if (section.name == ".rodata" && (mask & 1) != 0) {
            // Compare directly
            console.log("check .rodata");
            var filedata = new Uint8Array(getByteArr(section.data, section.size));
            var memdata = new Uint8Array(getByteArr(ptr(section.memaddr), section.size));
            for (var j = 0; j < section.size; j++) {
                if (filedata[j] != memdata[j]) {
                    console.log(".rodata\taddr:" + (section.memaddr + j).toString(16) + " file-mem:" + filedata[j].toString(16) + "-" + memdata[j].toString(16));
                }
            }
        } else if (section.name == ".text" && (mask & 2) != 0) {
            // Compare and get symbol
            console.log("check .text");
            var filedata = new Uint8Array(getByteArr(section.data, section.size));
            var memdata = new Uint8Array(getByteArr(ptr(section.memaddr), section.size));
            for (var j = 0; j < section.size; j++) {
                if (filedata[j] != memdata[j]) {
                    sym = getSymbol(section.memaddr + j);
                    console.log(".text\taddr:" + sym.funcname + "+" + sym.funcoff.toString(16) + " file-mem:" + filedata[j].toString(16) + "-" + memdata[j].toString(16));
                    if ((memdata[j] == 0x01 && memdata[j + 1] == 0x00 && memdata[j + 2] == 0x9f && memdata[j + 3] == 0xef) || (memdata[j] == 0xf0 && memdata[j + 1] == 0x01 && memdata[j + 2] == 0xf0 && memdata[j + 3] == 0xe7) || (memdata[j] == 0x01 && memdata[j + 1] == 0xde) || (memdata[j] == 0xf0 && memdata[j + 1] == 0xf7 && memdata[j + 2] == 0x00 && memdata[j + 3] == 0xa0) || (memdata[j] == 0x0d && memdata[j + 1] == 0x00 && memdata[j + 2] == 0x05 && memdata[j + 3] == 0x00) || (memdata[j] == 0x00 && memdata[j + 1] == 0x00 && memdata[j + 2] == 0x20 && memdata[j + 3] == 0xd4) || memdata[j] == 0xcc) {
                        console.log("software breakpoint detected!!!");
                        j = j + 4;
                    } else {
                        console.log("may be hook");
                    }
                }
            }
        } else if (section.name == ".got" && (mask & 4) != 0) {
            console.log("check .got");
            if (Process.pointerSize == 4) {
                var filedata = new Uint32Array(getByteArr(section.data, section.size));
                var memdata = new Uint32Array(getByteArr(ptr(section.memaddr), section.size));
                for (var j = 0; j < section.size / 4; j++) {
					var F = filedata[j];
					var M = memdata[j];
                    if (F + module.vmmin != M && F != M) {
                        var msym = getSymbol(M);
						var fsym = module.sym_2_str[module.dyn_2_name[section.memoff + j * 4]];
						if (msym.funcname != fsym) {
							console.log(".got " + j + "/" + section.size / 4 + "\taddr:" + (section.memaddr + j * 4).toString(16) + " file-mem:" + F.toString(16) + "-" + M.toString(16) + " " + fsym + "->" + msym.libname + "." + msym.funcname + "+" + msym.funcoff);
						}
                    }
                }
            } else {
                var filedata = new Uint32Array(getByteArr(section.data, section.size));
                var memdata = new Uint32Array(getByteArr(ptr(section.memaddr), section.size));
                for (var j = 0; j < section.size / 8; j++) {
                    var F = filedata[j * 2] * 0x100000000 + filedata[j * 2 + 1];
                    var M = memdata[j * 2] * 0x100000000 + memdata[j * 2 + 1];
                    if (F + module.vmmin != M && F != M) {
                        var msym = getSymbol(M);
						var fsym = module.sym_2_str[module.dyn_2_name[section.memoff + j * 4]];
						if (msym.funcname != fsym) {
							console.log(".got " + j + "/" + section.size / 8 + "\taddr:" + (section.memaddr + j * 8).toString(16) + " file-mem:" + F.toString(16) + "-" + M.toString(16) + " " + fsym + "->" + msym.libname + "." + msym.funcname + "+" + msym.funcoff);
						}
                    }
                }
            }
        } else if (section.name == ".got.plt" && (mask & 8) != 0) {
            console.log("check .got.plt");
            if (Process.pointerSize == 4) {
                var filedata = new Uint32Array(getByteArr(section.data, section.size));
                var memdata = new Uint32Array(getByteArr(ptr(section.memaddr), section.size));
                for (var j = 3; j < section.size / 4; j++) { // First 3 is special
					var F = filedata[j];
					var M = memdata[j];
                    if (F + module.vmmin != M && F != M) {
                        var msym = getSymbol(M);
						var fsym = module.sym_2_str[module.dyn_2_name[section.memoff + j * 4]];
						if (msym.funcname != fsym) {
							console.log(".got.plt " + j + "/" + section.size / 4 + "\taddr:" + (section.memaddr + j * 4).toString(16) + " file-mem:" + F.toString(16) + "-" + M.toString(16) + " " + fsym + "->" + msym.libname + "." + msym.funcname + "+" + msym.funcoff);
						}
                    }
                }
            } else {
                var filedata = new Uint32Array(getByteArr(section.data, section.size));
                var memdata = new Uint32Array(getByteArr(ptr(section.memaddr), section.size));
                for (var j = 0; j < section.size / 8; j++) {
                    var F = filedata[j * 2] * 0x100000000 + filedata[j * 2 + 1];
                    var M = memdata[j * 2] * 0x100000000 + memdata[j * 2 + 1];
                    if (F + module.vmmin != M && F != M) {
                        var msym = getSymbol(M);
						var fsym = module.sym_2_str[module.dyn_2_name[section.memoff + j * 4]];
						if (msym.funcname != fsym) {
							console.log(".got " + j + "/" + section.size / 8 + "\taddr:" + (section.memaddr + j * 8).toString(16) + " file-mem:" + F.toString(16) + "-" + M.toString(16) + " " + fsym + "->" + msym.libname + "." + msym.funcname + "+" + msym.funcoff);
						}
                    }
                }
            }
        }
    }
}

// Export function: check all loaded module consistence with file
/**
	nfilter : null for all modules, "libc.so" for libc.so
	mask : 0x1 for .rodata,  0x2 for .text,  0x4 for .got,  0x8 for .plt.got
*/
var global_symbols = new Array();
var modules = null;

function checkConsistency(nfilter, mask) {
    if (modules == null) {
        modules = getAllModules();
    }
    if (global_symbols.length == 0) {
        for (var i = 0; i < modules.length; i++) {
            // modules address/name/type
            var tp = modules[i].path.split("/");
            var path = tp[tp.length - 1];
            var modsym = Module.enumerateExportsSync(path);
            var modbase = new Object();
            modbase.address = modules[i].vmmin;
            modbase.name = "unknown";
            modbase.type = "modbase";
            modsym.push(modbase);
            modsym.sort(function(v1, v2) {
                return v1.address - v2.address;
            });
            for (var j = 0; j < modsym.length; j++) {
                modsym[j].path = path;
            }
            global_symbols = global_symbols.concat(modsym);
        }
    }

    for (var i = 0; i < modules.length; i++) {
        if (nfilter == null || modules[i].path.indexOf(nfilter) != -1) {
            if (getElfData(modules[i])) {
                compareMemory(modules[i], mask);
            }
        }
    }
}

function dumpModule(name) {
	if (modules == null) {
		modules = getAllModules();
	}
	var modindx = -1;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
			// Get file name
			modindx = i;
			break;
        }
    }
	if (modindx != -1) {
		var filepath = modules[modindx].path;
		var tp = filepath.split("/");
		var filename = tp[tp.length - 1];
		var newpath = "/sdcard/" + filename;
		var signature = getU32(ptr(modules[modindx].vmmin));
		var type = "unknown";
		var modsize = modules[modindx].vmmax - modules[modindx].vmmin;
		if (signature == 0) {
			if (filepath.indexOf(".so") != -1) { // Elf header erase
				type = "elf";
			}
		}
		else if (signature == 1179403647) {
			type = "elf";
		}
		else if (signature == 175727972) {
			type = "odex";
		}
		if (type == "elf") {
			var textindx = -1;
			var sections = null;	
			if (getElfData(modules[modindx])) {
				// Recover .text section
				sections = modules[modindx].sections;
				for (var j = 0; j < sections.length; j++) {
					if (sections[j].name == ".text") {
						textindx = j;
						break;
					}
				}
			}
			getCommandOutput("cp " + filepath + " " + newpath);
			var fmodule = open(newpath, O_WRONLY, 0);
			if (textindx != -1 && fmodule != -1) {
				lseek(fmodule, sections[textindx].fileoff, SEEK_SET); 
				write(fmodule, ptr(sections[textindx].memaddr), sections[textindx].size);
				close(fmodule);
				console.log("create decrytped file at:" + newpath + " size:" + modsize.toString(16));
			}		
		}
		else {
			var fmodule = open(newpath, O_CREAT | O_WRONLY, 0);
			if (fmodule != -1) {
				lseek(fmodule, 0, SEEK_SET); 
				write(fmodule, ptr(modules[modindx].vmmin), modsize);
				close(fmodule);
				console.log("create decrytped file at:" + newpath + " size:" + modsize.toString(16));
			}	
		}
	}
}

function parseDexOptHeader(np) {
	var result = new Object();
	result.dexOffset = 	getU32(np.add(8));
	result.dexLength = 	getU32(np.add(12));
	result.depsOffset = getU32(np.add(16));
	result.depsLength = getU32(np.add(20));
	result.optOffset = 	getU32(np.add(24));
	result.optLength = 	getU32(np.add(28));
	result.data = Memory.dup(np, 40);
	return result;
}

function parseDexHeader(np) {
	var result = new Object();
	result.fileSize = 		getU32(np.add(32));
	result.stringIdsSize = 	getU32(np.add(56));
	result.stringIdsOff = 	getU32(np.add(60));
	result.typeIdsSize = 	getU32(np.add(64));
	result.typeIdsOff = 	getU32(np.add(68));
	result.protoIdsSize = 	getU32(np.add(72));
	result.protoIdsOff = 	getU32(np.add(76));
	result.fieldIdsSize = 	getU32(np.add(80));
	result.fieldIdsOff = 	getU32(np.add(84));
	result.methodIdsSize = 	getU32(np.add(88));
	result.methodIdsOff = 	getU32(np.add(92));
	result.classDefsSize = 	getU32(np.add(96));
	result.classDefsOff =	getU32(np.add(100));
	result.data = Memory.dup(np, 112);
	return result;
}

function parseStringId() {
	
}

function dumpSingleDex(dexbase) {
	console.log("Dump dex file at:" + dexbase.toString(16));
	pOptHeader = getPt(dexbase + Process.pointerSize * 0);	// DexOptHeader
	optheader = parseDexOptHeader(pOptHeader);
	pHeader = getPt(dexbase + Process.pointerSize * 1);		// DexHeader
	header = parseDexHeader(pHeader);
	pStringIds = getPt(dexbase + Process.pointerSize * 2);	// DexStringId
	for (var i = 0; i < pHeader.stringIdsSize; i++) {
		
	}
	pTypeIds = getPt(dexbase + Process.pointerSize * 3);	// DexTypeId
	pFieldIds = getPt(dexbase + Process.pointerSize * 4);	// DexFieldId
	pMethodIds = getPt(dexbase + Process.pointerSize * 5);	// DexMethodId
	pProtoIds = getPt(dexbase + Process.pointerSize * 6);	// DexProtoId
	pClassDefs = getPt(dexbase + Process.pointerSize * 7);	// DexClassDef
	pLinkData = getPt(dexbase + Process.pointerSize * 8);	// DexLink
	pClassLookup = getPt(dexbase + Process.pointerSize * 9);// DexClassLookup
	
	var newpath = "/sdcard/" + dexbase.toString(16) + ".odex";
	var fmodule = open(newpath, O_CREAT | O_WRONLY, 0);
	if (fmodule == -1) {
		return;
	}
	
	console.log("Dumped dex " + newpath);
}

// Notice: first call to dumpDex() will fail (Frida bug?), cal second time will success
function dumpDex() { 
	var timeout = 2; // timeout set to 2s
	var dexaddr_array = []; // pointer string of DexFile struct, "0x432e1298","0x432e76f8","0x432e9b98", ...
	var finish = false;
	Java.perform(function () {  
		Java.choose("dalvik.system.DexFile", {                            
			"onMatch" : function(instance) {
				dexaddr_array.push(parseInt(instance.toString().split("@")[1], 16)); // dalvik.system.DexFile@0x432e1298           
			},
			"onComplete" : function() {
				finish = true;
			}
		});      
	}); 
	var count = 0;
	while (!finish) {// Wait 'choose' procedure finish
		sleep(1);
		if (count++ > timeout) {
			return;
		}
	}
	for (var i = 0; i < dexaddr_array.length; i++) {
		dumpSingleDex(dexaddr_array[i]);
	}
}

