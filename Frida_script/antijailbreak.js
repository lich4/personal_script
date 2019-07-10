function logtrace() {
    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n'); 
    //console.log(ObjC.classes.NSThread.callStackSymbols().toString());
}
Interceptor.attach(Module.findExportByName(null, "access"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("access " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "CFBundleGetAllBundles"), {
    onEnter: function(args) {
        console.log("CFBundleGetAllBundles");
    }
})
Interceptor.attach(Module.findExportByName(null, "chdir"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("chdir " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "chflags"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("chflags " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "connect"), {
    onEnter: function(args) {
        var port = Memory.readUShort(args[1].add(2));
        port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
        console.log("connect " + port);
        if (port == 22 || port == 27042) {
            Memory.writeUShort(args[1].add(2), 111);
        }
    }
})
Interceptor.attach(Module.findExportByName(null, "creat"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("creat " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "dladdr"), {
    info: null,
    onEnter: function(args) {
        this.info = args[1];
    },
    onLeave: function(ret) {
        if (this.info.isNull()) return;
        var dli_fname = Memory.readPointer(this.info);
        var dli_sname = Memory.readPointer(this.info.add(Process.pointerSize * 2));
        console.log("dladdr " + Memory.readUtf8String(dli_fname) + " " + Memory.readUtf8String(dli_sname));
    }
})
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("dlopen " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "dlopen_preflight"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("dlopen_preflight " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "dlsym"), {
    onEnter: function(args) {
        if (args[1].isNull()) return;
        console.log("dlsym " + Memory.readUtf8String(args[1]));
    }
})
Interceptor.attach(Module.findExportByName(null, "_dyld_get_image_header"), {
    onEnter: function(args) {
        console.log("dyld_get_image_header");
    }
})
Interceptor.attach(Module.findExportByName(null, "_dyld_get_image_name"), {
    onEnter: function(args) {
        args[0] = ptr("0");
        console.log("dyld_get_image_name");
    }
})
Interceptor.attach(Module.findExportByName(null, "_dyld_image_count"), {
    onEnter: function(args) {
        console.log("dyld_image_count");
    }
})
Interceptor.attach(Module.findExportByName(null, "_dyld_register_func_for_add_image"), {
    onEnter: function(args) {
        console.log("_dyld_register_func_for_add_image");
    }
})
Interceptor.attach(Module.findExportByName(null, "execl"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("execl " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "execle"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("execle " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "execlp"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("execlp " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "execv"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("execv " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "execve"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("execve " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "execvp"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("execvp " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "execvP"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("execvp " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "faccessat"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("faccessat " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "fopen"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("fopen " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "fork"), {
    onEnter: function(args) {
        console.log("fork");
    }
})
Interceptor.attach(Module.findExportByName(null, "fstatat"), {
    onEnter: function(args) {
        if (args[1].isNull()) return;
        console.log("fstatat " + Memory.readUtf8String(args[1]));
    }
})
Interceptor.attach(Module.findExportByName(null, "getenv"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var envname = Memory.readUtf8String(args[0]);
        if (envname != "TZ" && envname != "OS_ACTIVITY_DT_MODE" && 
            envname != "CFLOG_FORCE_STDERR") {
            console.log("getenv " + Memory.readUtf8String(args[0]));
        }
    },
    onLeave: function(ret) {
        if (!ret.isNull()) {
            var s = Memory.readUtf8String(ret);
            if (s.indexOf('Substrate') != -1) {
                ret.replace(ptr('0'));
            }
            console.log(Memory.readUtf8String(ret));
        }
    }
})
Interceptor.attach(Module.findExportByName(null, "getxattr"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("getxattr " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "link"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("link " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "listxattr"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var path = Memory.readUtf8String(args[0]);
        ['apt', 'Cydia', 'cydia', 'Substrate', 'substrate', 'stash', 'syslog', 
            'Ringtones', 'Wallpaper'].forEach(function(val, i) {
            if (path.indexOf(val) != -1) {
                Memory.writeUtf8String(args[0], "/x");
            }
        });
        ['/bin', '/etc', '/Appliations', '/usr'].forEach(function(val, i) {
            if (path.indexOf(val) == 0) {
                Memory.writeUtf8String(args[0], "/x");
            }
        });
        console.log("listxattr " + path);
    }
})
Interceptor.attach(Module.findExportByName(null, "lstat"), {
    block: false,
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var path = Memory.readUtf8String(args[0]);
        ['apt', 'Cydia', 'cydia', 'Substrate', 'substrate', 'stash', 'syslog', 
            'Ringtones', 'Wallpaper'].forEach(function(val, i) {
            if (path.indexOf(val) != -1) {
                this.block = true;
            }
        });
        ['/bin', '/etc', '/Appliations', '/usr'].forEach(function(val, i) {
            if (path.indexOf(val) == 0) {
                this.block = true;
            }
        });
        console.log("lstat " + path);
    },
    onLeave: function(ret) {
        if (this.block) ret.replace(ptr('-1'));
    }
})
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var path = Memory.readUtf8String(args[0]);
        ['apt', 'Cydia', 'cydia', 'Substrate', 'substrate', 'stash', 'syslog', 
            'Ringtones', 'Wallpaper'].forEach(function(val, i) {
            if (path.indexOf(val) != -1) {
                Memory.writeUtf8String(args[0], "/x");
            }
        });
        ['/bin', '/etc', '/Appliations', '/usr'].forEach(function(val, i) {
            if (path.indexOf(val) == 0) {
                Memory.writeUtf8String(args[0], "/x");
            }
        });
        console.log("open " + path);
    }
})
Interceptor.attach(Module.findExportByName(null, "openat"), {
    onEnter: function(args) {
        if (args[1].isNull()) return;
        console.log("openat " + Memory.readUtf8String(args[1]));
    }
})
Interceptor.attach(Module.findExportByName(null, "opendir"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("opendir " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "__opendir2"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("opendir2 " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "popen"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("popen " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        console.log("ptrace");
    }
})
Interceptor.attach(Module.findExportByName(null, "readlink"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("readlink " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "realpath"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("realpath " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "realpath$DARWIN_EXTSN"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("realpath$DARWIN_EXTSN " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "stat"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var name = Memory.readUtf8String(args[0]);
        if (name == '/Applications/Cydia.app') {
            Memory.writeUtf8String(args[0], "/x")
        }
        console.log("stat " + name);
    }
})
Interceptor.attach(Module.findExportByName(null, "statfs"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("statfs " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "symlink"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("symlink " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "syscall"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("syscall " + args[0].toInt32());
    }
})
Interceptor.attach(Module.findExportByName(null, "sysctl"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var nlen = args[1].toInt32();
        var name1 = 0, name2 = 0;
        var s = 'sysctl ';
        for (var i = 0; i < nlen && i < 2; i++) {
            if (i == 0) name1 = Memory.readS32(args[0].add(4 * i));
            if (i == 1) name2 = Memory.readS32(args[0].add(4 * i));
            s += Memory.readS32(args[0].add(4 * i)) + ' ';
        }
        console.log(s);
        if (name1 == 1 && name2 == 4) {
            Memory.writeS32(args[0].add(4), 1);
        }
    }
})
Interceptor.attach(Module.findExportByName(null, "sysctlbyname"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("sysctlbyname " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "system"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        console.log("system " + Memory.readUtf8String(args[0]));
    }
})
Interceptor.attach(Module.findExportByName(null, "task_for_pid"), {
    onEnter: function(args) {
        console.log("task_for_pid");
    }
})
Interceptor.attach(Module.findExportByName(null, "uname"), {
    name: null,
    onEnter: function(args) {
        this.name = args[0];
        console.log("uname");
    },
    onLeave: function(ret) {
       Memory.writeUtf8String(this.name.add(0x300), "Darwin"); // replace Marijuan
    }
})
Interceptor.attach(Module.findExportByName(null, "vfork"), {
    onEnter: function(args) {
        console.log("vfork");
    }
})

var LSCanOpenURLManager = ObjC.classes._LSCanOpenURLManager;
var NSData = ObjC.classes.NSData;
var NSFileManager = ObjC.classes.NSFileManager;
var NSProcessInfo = ObjC.classes.NSProcessInfo;
var NSString = ObjC.classes.NSString;
var UIApplication = ObjC.classes.UIApplication;

Interceptor.attach(LSCanOpenURLManager["- canOpenURL:publicSchemes:privateSchemes:XPCConnection:error:"].implementation, {
    onEnter: function(args) {
        console.log("LSCanOpenURLManager canOpenURL:publicSchemes:privateSchemes:XPCConnection:error: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(LSCanOpenURLManager["- internalCanOpenURL:publicSchemes:privateSchemes:XPCConnection:error:"].implementation, {
    onEnter: function(args) {
        console.log("LSCanOpenURLManager internalCanOpenURL:publicSchemes:privateSchemes:XPCConnection:error: " + ObjC.Object(args[2]).toString());
    }
})
if (LSCanOpenURLManager["+ queryForApplicationsAvailableForOpeningURL:"] != undefined) {
    Interceptor.attach(LSCanOpenURLManager["+ queryForApplicationsAvailableForOpeningURL:"].implementation, {
        onEnter: function(args) {
            console.log("LSCanOpenURLManager queryForApplicationsAvailableForOpeningURL: " + ObjC.Object(args[2]).toString());
        }
    })
} else if (LSCanOpenURLManager["+ queryForApplicationsAvailableForOpeningURL:legacySPI:"] != undefined) {
    Interceptor.attach(LSCanOpenURLManager["+ queryForApplicationsAvailableForOpeningURL:legacySPI:"].implementation, {
        onEnter: function(args) {
            console.log("LSCanOpenURLManager queryForApplicationsAvailableForOpeningURL:legacySPI: " + ObjC.Object(args[2]).toString());
        }
    })
}
Interceptor.attach(NSData["+ dataWithContentsOfURL:"].implementation, {
    onEnter: function(args) {
        console.log("NSData dataWithContentsOfURL: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSData["- initWithContentsOfFile:"].implementation, {
    onEnter: function(args) {
        console.log("NSData initWithContentsOfFile: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSData["- writeToFile:atomically:"].implementation, {
    onEnter: function(args) {
        console.log("NSData writeToFile:atomically: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSData["- writeToFile:options:error:"].implementation, {
    onEnter: function(args) {
        console.log("NSData writeToFile:options:error: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSData["- writeToURL:atomically:"].implementation, {
    onEnter: function(args) {
        console.log("NSData writeToURL:atomically: " + ObjC.Object(args[2]).path().toString());
    }
})
Interceptor.attach(NSData["- writeToURL:options:error:"].implementation, {
    onEnter: function(args) {
        console.log("NSData writeToURL:options:error: " + ObjC.Object(args[2]).path().toString());
    }
})
Interceptor.attach(NSFileManager["- changeCurrentDirectoryPath:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager changeCurrentDirectoryPath: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSFileManager["- contentsAtPath:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager contentsAtPath: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSFileManager["- contentsOfDirectoryAtPath:error:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager contentsOfDirectoryAtPath:error: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();
        ['apt', 'Cydia', 'cydia', 'Substrate', 'substrate', 'stash', 'syslog', 
            'Ringtones', 'Wallpaper'].forEach(function(val, i) {
            if (path.indexOf(val) != -1) {
                args[2] = NSString.alloc().init().handle;
            }
        });
        ['/bin', '/etc', '/Appliations', '/usr'].forEach(function(val, i) {
            if (path.indexOf(val) == 0) {
                args[2] = NSString.alloc().init().handle;
            }
        });
        console.log("NSFileManager fileExistsAtPath: " + path);
    }
})
Interceptor.attach(NSFileManager["- fileExistsAtPath:isDirectory:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager fileExistsAtPath: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSFileManager["- isReadableFileAtPath:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager isReadableFileAtPath: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSFileManager["- isWritableFileAtPath:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager isWritableFileAtPath: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSFileManager["- isExecutableFileAtPath:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager isExecutableFileAtPath: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSFileManager["- isDeletableFileAtPath:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager isDeletableFileAtPath: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSFileManager["- removeItemAtPath:error:"].implementation, {
    onEnter: function(args) {
        console.log("NSFileManager removeItemAtPath:error: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSProcessInfo["- environment"].implementation, {
    onEnter: function(args) {
        console.log("NSProcessInfo environment");
    },
    onLeave: function(ret) {
        var NSDictionary = ObjC.classes.NSDictionary;
        ret.replace(NSDictionary.alloc().init());
    }
})
Interceptor.attach(NSString["- writeToFile:atomically:"].implementation, {
    onEnter: function(args) {
        console.log("NSString writeToFile:atomically: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSString["- initWithContentsOfFile:"].implementation, {
    onEnter: function(args) {
        console.log("NSString initWithContentsOfFile: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSString["+ stringWithContentsOfURL:"].implementation, {
    onEnter: function(args) {
        console.log("NSString stringWithContentsOfURL: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSString["- writeToFile:atomically:encoding:error:"].implementation, {
    onEnter: function(args) {
        console.log("NSString writeToFile:atomically:encoding:error: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(NSString["- writeToURL:atomically:"].implementation, {
    onEnter: function(args) {
        console.log("NSString writeToURL:atomically: " + ObjC.Object(args[2]).path().toString());
    }
})
Interceptor.attach(NSString["- writeToURL:atomically:encoding:error:"].implementation, {
    onEnter: function(args) {
        console.log("NSString writeToURL:atomically:encoding:error: " + ObjC.Object(args[2]).path().toString());
    }
})
Interceptor.attach(UIApplication["- canOpenURL:"].implementation, {
    onEnter: function(args) {
        console.log("UIApplication canOpenURL: " + ObjC.Object(args[2]).toString());
    }
})
Interceptor.attach(UIApplication["- openURL:"].implementation, {
    onEnter: function(args) {
        console.log("UIApplication openURL: " + ObjC.Object(args[2]).toString());
    }
})
