var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

var NSData = ObjC.classes.NSData;
var NSString = ObjC.classes.NSString;
var NSFileManager = ObjC.classes.NSFileManager;


function str(s) {
    return Memory.allocUtf8String(s);
}

function nsstr(str) {
    return ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
}


function nsstr2nsdata(nsstr) {
    return nsstr.dataUsingEncoding_(4);
}


function nsdata2nsstr(nsdata) {
    return ObjC.classes.NSString.alloc().initWithData_encoding_(nsdata, 4);
}


function callstack() {
    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");
}

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function getNSString(str) {
    return NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
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

function malloc(size) {
    return Memory.alloc(size);
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

function modload(modpath) {
    var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);
    dlopen(str(modpath), 1);
}

function print_sysctl_str(name, sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf) {
    Memory.writeU32(sizep, 2);
    Memory.writeU32(bufsize, bsize);
    sysctlnametomib(str(name), mibp, sizep);
    sysctl(mibp, 2, buf, bufsize, ptr("0"), 0);
    console.log(name, getStr(buf));
    sysctlbyname(str(name), buf, bufsize, ptr("0"), 0);
    console.log(name, getStr(buf));
}

function print_sysctl_u32(name, sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf) {
    Memory.writeU32(sizep, 2);
    Memory.writeU32(bufsize, bsize);
    sysctlnametomib(str(name), mibp, sizep);
    sysctl(mibp, 2, buf, bufsize, ptr("0"), 0);
    console.log(name, getU32(buf));
    Memory.writeU32(bufsize, bsize);
    sysctlbyname(str(name), buf, bufsize, ptr("0"), 0);
    console.log(name, getU32(buf));
}

var sleep = getExportFunction("f", "sleep", "void", ["int"]);

function get_location() {
    var waitforstart = 2;
    var location = "please enable location service in iOS settings";
    var locman = null;
    var locproxy = null;
    var CLLocationManager = ObjC.classes.CLLocationManager;
    const MyConnectionDelegateProxy = ObjC.registerClass({
        super: ObjC.classes.NSObject,
        protocols: [ObjC.protocols.CLLocationManagerDelegate],
        methods: {
            '- locationManager:didUpdateLocations:': {
                types: ObjC.protocols.CLLocationManagerDelegate.methods['- locationManager:didUpdateLocations:'].types,
                implementation: function (man, locs) {
                    var loc = locs.lastObject();
                    location = "coordinate=" + loc.coordinate() + ",altitude=" + loc.altitude() + 
                        ",horizontalAccuracy=" + loc.horizontalAccuracy() + ",verticalAccuracy=" + loc.verticalAccuracy() +
                        ",course=" + loc.course() + ",speed=" + loc.speed() + ",timestamp=" + loc.timestamp();
                    waitforstart = false;
                }
            },
            '- locationManager:didFailWithError:': {
                types: ObjC.protocols.CLLocationManagerDelegate.methods['- locationManager:didFailWithError:'].types,
                implementation: function (man, err) {
                    location = "get location error " + err.toString();
                    waitforstart = false;
                }
            }
        }
    });
        
    ObjC.schedule(ObjC.mainQueue, function() {
        locman = CLLocationManager.alloc().init();
        locproxy = MyConnectionDelegateProxy.alloc().init();
        locman.setDelegate_(locproxy);
        locman.requestAlwaysAuthorization();
        locman.setDesiredAccuracy_(-1.0);
        locman.startUpdatingLocation();
    })
    while (waitforstart--) {
        sleep(1);
    }
    locman.stopUpdatingLocation();
    return location;
}

function geterr() {
    var strerror = getExportFunction("f", "strerror", "pointer", ["int"]);
    var errno = getExportFunction("d", "errno");
    return Memory.readUtf8String(strerror(errno.toInt32()));
}

function get_networkinfo() {
    var AF_INET = 2;
    var AF_INET6 = 30;
    var AF_LINK = 18;
    var bufsize = 256;
    var buf = Memory.alloc(bufsize);
    var int2family = function (i) {
        return { "2": "AF_INET", "18": "AF_LINK", "30": "AF_INET6" }[i.toString()];
    }
    var getifaddrs = getExportFunction("f", "getifaddrs", "int", ["pointer"]);
    var inet_ntop = getExportFunction("f", "inet_ntop", "pointer", ["int", "pointer", "pointer", "int"]);
    var paddrs = Memory.alloc(Process.pointerSize);
    getifaddrs(paddrs);
    var caddr = Memory.readPointer(paddrs);
    while (caddr != 0) {
        var ifa_addr = Memory.readPointer(caddr.add(Process.pointerSize * 3));
        var ifa_netmask = Memory.readPointer(caddr.add(Process.pointerSize * 4));
        var ifa_dstaddr = Memory.readPointer(caddr.add(Process.pointerSize * 5));
        var ifa_data = Memory.readPointer(caddr.add(Process.pointerSize * 6));
        var ifa_name = Memory.readPointer(caddr.add(Process.pointerSize));
        var name = Memory.readUtf8String(Memory.readPointer(caddr.add(Process.pointerSize)));
        var family = Memory.readU8(ifa_addr.add(1));
        var s_addr = "none";
        var s_netmask = "none";
        var s_dstaddr = "none";
        var ibytes = 0, obytes = 0, ipackets = 0, opackets = 0, baudrate = 0;
        if (!ifa_addr.isNull()) {
            if (!inet_ntop(family, ifa_addr.add(4), buf, bufsize).isNull()) {
                s_addr = Memory.readUtf8String(buf);
            }
        }
        if (!ifa_netmask.isNull()) {
            if (!inet_ntop(family, ifa_netmask.add(4), buf, bufsize).isNull()) {
                s_netmask = Memory.readUtf8String(buf);
            }
        }
        if (!ifa_dstaddr.isNull()) {
            if (!inet_ntop(family, ifa_dstaddr.add(4), buf, bufsize).isNull()) {
                var s_dstaddr = Memory.readUtf8String(buf);
            }
        }
        if (!ifa_addr.isNull()) {
            baudrate = Memory.readU32(ifa_addr.add(16));
            ipackets = Memory.readU32(ifa_addr.add(20));
            opackets = Memory.readU32(ifa_addr.add(28));
            ibytes = Memory.readU32(ifa_addr.add(40));
            obytes = Memory.readU32(ifa_addr.add(44));
        }
        console.log(name + ",family:" + family + ",addr:" + s_addr + ",netmask:" +
            s_netmask + ",dstaddr:" + s_dstaddr + ",ibytes:" + ibytes + ",obytes:" + obytes +
            ",ipackets:" + ipackets + ",opackets:" + opackets + ",baudrate:" + baudrate);
        caddr = Memory.readPointer(caddr);
    }
    var SCNetworkReachabilityCreateWithAddress = getExportFunction("f", "SCNetworkReachabilityCreateWithAddress",
        "pointer", ["pointer", "pointer"]);
    var SCNetworkReachabilityGetFlags = getExportFunction("f", "SCNetworkReachabilityGetFlags",
        "int", ["pointer", "pointer"]);
    Memory.writeU64(buf, 0);
    Memory.writeU64(buf.add(8), 0);
    Memory.writeU8(buf, 16);
    Memory.writeU8(buf.add(1), AF_INET);
    var defaultRouteReachability = SCNetworkReachabilityCreateWithAddress(ptr('0'), buf);
    var SCNetworkReachabilityFlags = Memory.alloc(4);
    SCNetworkReachabilityGetFlags(defaultRouteReachability, SCNetworkReachabilityFlags);
    console.log("SCNetworkReachabilityFlags", Memory.readU32(SCNetworkReachabilityFlags));
}

function get_deviceinfo() {
    var bsize = 256;
    var buf = Memory.alloc(bsize);
    var bufsize = Memory.alloc(4);

    var _SYS_NAMELEN = 256;
    var uname = getExportFunction("f", "uname", "int", ["pointer"]);
    var utsname = Memory.alloc(_SYS_NAMELEN * 5);
    uname(utsname);
    console.log("uname.sysname", getStr(utsname.add(0 * _SYS_NAMELEN)));
    console.log("uname.nodename", getStr(utsname.add(1 * _SYS_NAMELEN)));
    console.log("uname.release", getStr(utsname.add(2 * _SYS_NAMELEN)));
    console.log("uname.version", getStr(utsname.add(3 * _SYS_NAMELEN)));
    console.log("uname.machine", getStr(utsname.add(4 * _SYS_NAMELEN)));

    var sysctlbyname = getExportFunction("f", "sysctlbyname", "int", 
        ["pointer", "pointer", "pointer", "pointer", "int"]);
    var sysctl = getExportFunction("f", "sysctl", "int", 
        ["pointer", "int", "pointer", "pointer", "pointer", "int"]);
    var sysctlnametomib = getExportFunction("f", "sysctlnametomib", "int",
        ["pointer", "pointer", "pointer"]);
    var mibp = Memory.alloc(8);
    var sizep = Memory.alloc(4);
    print_sysctl_str("kern.osrelease", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_str("kern.version", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_str("kern.hostname", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("kern.boottime", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_str("kern.osversion", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_str("hw.machine", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_str("hw.model", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("hw.ncpu", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("hw.availcpu", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("hw.physmem", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("hw.memsize", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("hw.usermem", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("hw.l1icachesize", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("hw.l1dcachesize", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);
    print_sysctl_u32("hw.l2cachesize", sysctlbyname, sysctlnametomib, sysctl, mibp, sizep, bufsize, bsize, buf);

    var UIDevice = ObjC.classes.UIDevice.currentDevice();
    console.log("UIDevice.localizedModel", UIDevice.localizedModel());
    console.log("UIDevice.systemVersion", UIDevice.systemVersion());
    console.log("UIDevice.model", UIDevice.model());
    console.log("UIDevice.name", UIDevice.name());
    console.log("UIDevice.systemName", UIDevice.systemName());
    console.log("UIDevice.orientation", UIDevice.orientation());
    console.log("UIDevice.identifierForVendor", UIDevice.identifierForVendor());

    var NSProcessInfo = ObjC.classes.NSProcessInfo.processInfo();
    console.log("NSProcessInfo.hostName", NSProcessInfo.hostName());
    console.log("NSProcessInfo.operatingSystemVersionString", NSProcessInfo.operatingSystemVersionString());
    console.log("NSProcessInfo.operatingSystemVersion", NSProcessInfo.operatingSystemVersion());
    console.log("NSProcessInfo.processorCount", NSProcessInfo.processorCount());
    console.log("NSProcessInfo.activeProcessorCount", NSProcessInfo.activeProcessorCount());
    console.log("NSProcessInfo.physicalMemory", NSProcessInfo.physicalMemory());
    console.log("NSProcessInfo.systemUptime", NSProcessInfo.systemUptime());

    modload('/System/Library/Frameworks/AdSupport.framework/AdSupport');
    var ASIdentifierManager = ObjC.classes.ASIdentifierManager.sharedManager();
    console.log("ASIdentifierManager.advertisingIdentifier", ASIdentifierManager.advertisingIdentifier());
    console.log("ASIdentifierManager.isAdvertisingTrackingEnabled", ASIdentifierManager.isAdvertisingTrackingEnabled());

    ObjC.schedule(ObjC.mainQueue, function() {
        var UIWebView = ObjC.classes.UIWebView.alloc().init();
        var useragent = UIWebView.stringByEvaluatingJavaScriptFromString_(nsstr("navigator.userAgent"));
        console.log("UserAgent", useragent);
    })

    var ctinfo = ObjC.classes.CTTelephonyNetworkInfo.alloc().init();
    var carrier = ctinfo.subscriberCellularProvider();
    console.log("CTCarrier.carrierName", carrier.carrierName());
    console.log("CTCarrier.mobileCountryCode", carrier.mobileCountryCode());
    console.log("CTCarrier.mobileNetworkCode", carrier.mobileNetworkCode());
    console.log("CTCarrier.isoCountryCode", carrier.isoCountryCode());
    console.log("CTTelephonyNetworkInfo.currentRadioAccessTechnology", ctinfo.currentRadioAccessTechnology());

    var NSLocale = ObjC.classes.NSLocale.currentLocale();
    console.log("NSLocale.localeIdentifier", NSLocale.localeIdentifier());
    console.log("NSLocale.languageCode", NSLocale.languageCode());
    console.log("NSLocale.collatorIdentifier", NSLocale.collatorIdentifier());
    console.log("NSLocale.countryCode", NSLocale.countryCode());
    console.log("NSLocale.currencySymbol", NSLocale.currencySymbol());
    console.log("NSLocale.currencyCode", NSLocale.currencyCode());

    var NSUserDefaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
    console.log("NSUserDefaults.NSLanguages", NSUserDefaults.objectForKey_(nsstr('NSLanguages')));
    console.log("NSUserDefaults.ApplePasscodeKeyboards", NSUserDefaults.objectForKey_(nsstr('ApplePasscodeKeyboards')));
    console.log("NSUserDefaults.AppleLanguages", NSUserDefaults.objectForKey_(nsstr('AppleLanguages')));
    console.log("NSUserDefaults.AppleKeyboards", NSUserDefaults.objectForKey_(nsstr('AppleKeyboards')));
    console.log("NSUserDefaults.AppleKeyboardsExpanded", NSUserDefaults.objectForKey_(nsstr('AppleKeyboardsExpanded')));

    var UITextInputMode = ObjC.classes.UITextInputMode;
    console.log("UITextInputMode.primaryLanguage", UITextInputMode.currentInputMode().primaryLanguage());
    var tinputmodes = UITextInputMode.activeInputModes();
    for (var i = 0; i < tinputmodes.count(); i++) {
        console.log("UITextInputMode.activeInputModes", tinputmodes.objectAtIndex_(i).primaryLanguage());
    }

    var key = ObjC.classes.UIKeyboardInputModeController.sharedInputModeController();
    console.log("UIKeyboardInputMode.currentInputMode", key.currentInputMode().identifier());
    var kinputmods = key.extensionInputModes();
    for (var i = 0; i < kinputmods.count(); i++) {
        console.log("UIKeyboardInputMode.extensionInputModes", tinputmodes.objectAtIndex_(i).identifier());
    }

    var NSTimeZone = ObjC.classes.NSTimeZone;
    console.log("systemTimeZone", NSTimeZone.systemTimeZone().name());
    console.log("defaultTimeZone", NSTimeZone.defaultTimeZone().name());
    console.log("localTimeZone", NSTimeZone.localTimeZone().name());

    var UIDevice = ObjC.classes.UIDevice.currentDevice();
    console.log("UIDevice.batteryMonitoringEnabled", UIDevice.isBatteryMonitoringEnabled());
    UIDevice.setBatteryMonitoringEnabled_(1);
    console.log("UIDevice.batteryState", UIDevice.batteryState());
    console.log("UIDevice.batteryLevel", UIDevice.batteryLevel());

    var NSDocumentDirectory = 9;
    var NSUserDomainMask = 1;
    var error = Memory.alloc(4);
    
    var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains",
        "pointer", ["int", "int", "int"]);
    var docpaths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
    var docpath = ObjC.Object(docpaths).lastObject();
    var attrs = NSFileManager.defaultManager().attributesOfFileSystemForPath_error_(docpath, error);
    console.log("NSFileManager.NSFileSystemSize", attrs.objectForKey_(nsstr("NSFileSystemSize")));
    console.log("NSFileManager.NSFileSystemFreeSize", attrs.objectForKey_(nsstr("NSFileSystemFreeSize")));

    var UIScreen = ObjC.classes.UIScreen.mainScreen();
    var UIApplication = ObjC.classes.UIApplication.sharedApplication();
    console.log("UIScreen.bounds", UIScreen.bounds());
    console.log("UIScreen.nativeBounds", UIScreen.nativeBounds());
    console.log("UIScreen.brightness", UIScreen.brightness());
    console.log("UIApplication.idleTimerDisabled", UIApplication.isIdleTimerDisabled());

    var AVAudioSession = ObjC.classes.AVAudioSession.sharedInstance();
    console.log("AVAudioSession.outputVolume", AVAudioSession.outputVolume());
    console.log("AVAudioSession.inputLatency", AVAudioSession.inputLatency());
    console.log("AVAudioSession.outputLatency", AVAudioSession.outputLatency());
    console.log("AVAudioSession.IOBufferDuration", AVAudioSession.IOBufferDuration());
    console.log("AVAudioSession.Headphones", AVAudioSession.currentRoute().outputs().lastObject().portType());
}
