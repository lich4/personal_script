var NSData = ObjC.classes.NSData;
var NSString = ObjC.classes.NSString;

function unicode2str(str) {
    var ret = "";
    var ustr = "";
 
    for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        var code16 = code.toString(16);
        if (code < 0xf) {
            ustr = "\\u" + "000" + code16;
        } else if(code < 0xff){
            ustr = "\\u" + "00" + code16;
        } else if(code < 0xfff){
            ustr = "\\u" + "0" + code16;
        } else {
            ustr = "\\u" + code16;
        }  
        ret += ustr;
    }
    return ret;
}

/* JavaScript String -> NSString */
function str(s) {
    return Memory.allocUtf8String(s);
}

function nsstr(str) {
    return ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
}

/* NSString -> NSData */
function nsstr2nsdata(nsstr) {
    return nsstr.dataUsingEncoding_(4);
}

/* NSData -> NSString */
function nsdata2nsstr(nsdata) {
    return ObjC.classes.NSString.alloc().initWithData_encoding_(nsdata, 4);
}

/* Print Native Callstack */
function callstack() {
    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");
}

function callstack_() {
	console.log(ObjC.classes.NSThread.callStackSymbols().toString());
}

/* c function wrapper */
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

function getscreensize() {
    var UIScreen = ObjC.classes.UIScreen;
    return UIScreen.mainScreen().bounds()[1];
}

function click(x, y) {
    // https://github.com/zjjno/PTFakeTouchDemo.git 编译为dylib
    modload("/Library/MobileSubstrate/DynamicLibraries/PTFakeTouch.dylib")
    var touchxy = getExportFunction("f", "touchxy", "void", ["int", "int"]);
    touchxy(x, y);
}

function _utf8_encode(string) {
    string = string.replace(/\r\n/g, "\n");
    var utftext = "";
    for (var n = 0; n < string.length; n++) {
        var c = string.charCodeAt(n);
        if (c < 128) {
            utftext += String.fromCharCode(c);
        } else if ((c > 127) && (c < 2048)) {
            utftext += String.fromCharCode((c >> 6) | 192);
            utftext += String.fromCharCode((c & 63) | 128);
        } else {
            utftext += String.fromCharCode((c >> 12) | 224);
            utftext += String.fromCharCode(((c >> 6) & 63) | 128);
            utftext += String.fromCharCode((c & 63) | 128);
        }
    }
    return utftext;
}

// 获取keychain数据
function getkeychain() {
    var NSMutableDictionary=ObjC.classes.NSMutableDictionary;
    var kCFBooleanTrue = ObjC.Object(getExportFunction("d", "kCFBooleanTrue"));
    var kSecReturnAttributes = ObjC.Object(getExportFunction("d", "kSecReturnAttributes"));
    var kSecMatchLimitAll = ObjC.Object(getExportFunction("d", "kSecMatchLimitAll"));
    var kSecMatchLimit = ObjC.Object(getExportFunction("d", "kSecMatchLimit"));
    var kSecClassGenericPassword = ObjC.Object(getExportFunction("d", "kSecClassGenericPassword"));
    var kSecClassInternetPassword = ObjC.Object(getExportFunction("d", "kSecClassInternetPassword"));
    var kSecClassCertificate = ObjC.Object(getExportFunction("d", "kSecClassCertificate"));
    var kSecClassKey = ObjC.Object(getExportFunction("d", "kSecClassKey"));
    var kSecClassIdentity = ObjC.Object(getExportFunction("d", "kSecClassIdentity"));
    var kSecClass = ObjC.Object(getExportFunction("d","kSecClass"));

    var query = NSMutableDictionary.alloc().init();
    var SecItemCopyMatching = getExportFunction("f", "SecItemCopyMatching", "int", ["pointer", "pointer"]);
    [kSecClassGenericPassword, kSecClassInternetPassword, kSecClassCertificate, kSecClassKey, 
        kSecClassIdentity].forEach(function(secItemClass) {
            query.setObject_forKey_(kCFBooleanTrue, kSecReturnAttributes);
            query.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit);
            query.setObject_forKey_(secItemClass, kSecClass);
            var result = Memory.alloc(8);
            Memory.writePointer(result, ptr("0"));
            SecItemCopyMatching(query.handle, result);
            var pt = Memory.readPointer(result);
            if (!pt.isNull()) {
                console.log(ObjC.Object(pt).toString());
            }
        }
    )
}

/* Base64 Encode */
function base64(input) {
    var _keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    var output = "";
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var i = 0;
    input = _utf8_encode(input);
    while (i < input.length) {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);
        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;
        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }
        output = output + _keyStr.charAt(enc1) + _keyStr.charAt(enc2) + _keyStr.charAt(enc3) + _keyStr.charAt(enc4);
    }
    return output;
}

/* Get KeyBlockSize from SecKeyRef */
function getPubkeyBlocksize(seckeyref) {
    var SecKeyGetBlockSize = new NativeFunction(Module.findExportByName(null, "SecKeyGetBlockSize"), "int", ["pointer"]);
    return SecKeyGetBlockSize(seckeyref);
}

/* Get RSA Public Key from SecKeyRef */
function getPubkeyFromKeyref(seckeyref) {
    var seckeyref = ObjC.classes.CBKeyStore.getConsultPasswordPublicKey();
    var publicTag = nsstr2nsdata(nsstr("com.your.company.publickey"));
    var queryPublicKey = ObjC.classes.NSMutableDictionary.alloc().init();
    var kSecClassKey = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecClassKey")));
    var kSecAttrApplicationTag = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecAttrApplicationTag")));
    var kSecAttrKeyTypeRSA = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecAttrKeyTypeRSA")));
    var kSecAttrKeyType = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecAttrKeyType")));
    var kSecValueRef = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecValueRef")));
    var kSecReturnData = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecReturnData")));
    var kSecClass = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecClass")));
    var yes = ObjC.classes.NSNumber.numberWithBool_(1);
    queryPublicKey.setObject_forKey_(kSecClassKey, kSecClass);
    queryPublicKey.setObject_forKey_(publicTag, kSecAttrApplicationTag);
    queryPublicKey.setObject_forKey_(kSecAttrKeyTypeRSA, kSecAttrKeyType);
    var attributes = queryPublicKey.mutableCopy();
    attributes.setObject_forKey_(seckeyref, kSecValueRef);
    attributes.setObject_forKey_(yes, kSecReturnData);
    var publicKeyBits = Memory.alloc(Process.pointerSize);
    Memory.writePointer(publicKeyBits, ptr("0"));
    var SecItemAdd = new NativeFunction(Module.findExportByName(null, "SecItemAdd"), "int", ["pointer", "pointer"]);
    var SecItemDelete = new NativeFunction(Module.findExportByName(null, "SecItemDelete"), "int", ["pointer"]);
    SecItemDelete(queryPublicKey.handle);
    var sanityCheck = SecItemAdd(attributes.handle, publicKeyBits);
    if (sanityCheck == 0) console.log("success");
    else console.log("failure");
    return ObjC.Object(Memory.readPointer(publicKeyBits));
}

/* Get all modules */
function getmodule() {
	var modules = Process.enumerateModulesSync();
	return modules.map(function (item) {
		return item['path'];
	});
}

/* Get all class in module */
function getmoduleclass(module) {
	if (module == null) {
		module = Process.enumerateModulesSync()[0]['path'];
	}
	var pcount = Memory.alloc(4);
	Memory.writeU32(pcount, 0);
	var objc_copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, "objc_copyClassNamesForImage"), "pointer", ["pointer", "pointer"]);
	var classptrarr = objc_copyClassNamesForImage(Memory.allocUtf8String(module), pcount);
	var count = Memory.readU32(pcount);
	var result = Array();
	for (var i = 0; i < count; i++) {
		var classptr = Memory.readPointer(classptrarr.add(Process.pointerSize * i));
		result.push(Memory.readUtf8String(classptr));
	}
	return result;
}

function getclassmodule(classname) {
    var objc_getClass = new NativeFunction(Module.findExportByName(null, "objc_getClass"), "pointer", ["pointer"]);
    var class_getImageName = new NativeFunction(Module.findExportByName(null, "class_getImageName"), "pointer",
        ["pointer"]);
    var class_ = objc_getClass(Memory.allocUtf8String(classname));
    return Memory.readUtf8String(class_getImageName(class_));
}

function getsymbolmodule(symbolname) {
    var dladdr = new NativeFunction(Module.findExportByName(null, "dladdr"), "int", ["pointer", "pointer"]);
    var info = Memory.alloc(Process.pointerSize * 4);
    dladdr(Module.findExportByName(null, symbolname), info);
    return {
        "fname": Memory.readUtf8String(Memory.readPointer(info)),
        "fbase": Memory.readPointer(info.add(Process.pointerSize)),
        "sname": Memory.readUtf8String(Memory.readPointer(info.add(Process.pointerSize * 2))),
        "saddr": Memory.readPointer(info.add(Process.pointerSize * 3)),
    }
}

function getaddressmodule(address) {
    var dladdr = new NativeFunction(Module.findExportByName(null, "dladdr"), "int", ["pointer", "pointer"]);
    var info = Memory.alloc(Process.pointerSize * 4);
    dladdr(ptr(address), info);
    return {
        "fname": Memory.readUtf8String(Memory.readPointer(info)),
        "fbase": Memory.readPointer(info.add(Process.pointerSize)),
        "sname": Memory.readUtf8String(Memory.readPointer(info.add(Process.pointerSize * 2))),
        "saddr": Memory.readPointer(info.add(Process.pointerSize * 3)),
    }
}

/* Get Objective-C Method of class */
function getclassmethod(classname) {
    var objc_getClass = new NativeFunction(Module.findExportByName(null, "objc_getClass"), "pointer", ["pointer"]);
    var objc_getMetaClass = new NativeFunction(Module.findExportByName(null, "objc_getMetaClass"), "pointer", ["pointer"]);
    var class_ = objc_getClass(Memory.allocUtf8String(classname));
    var metaclass_ = objc_getMetaClass(Memory.allocUtf8String(classname));
    var pcount = Memory.alloc(4);
    Memory.writeU32(pcount, 0);
    var class_copyMethodList = new NativeFunction(Module.findExportByName(null, "class_copyMethodList"), "pointer", ["pointer", "pointer"]);
    var method_getName = new NativeFunction(Module.findExportByName(null, "method_getName"), "pointer", ["pointer"]);
    var method_getImplementation = new NativeFunction(Module.findExportByName(null, "method_getImplementation"), "pointer", ["pointer"]);
    var methodptrarr = class_copyMethodList(class_, pcount);
    var count = Memory.readU32(pcount);
	var result = new Array();
    for (var i = 0; i < count; i++) {
        var method = Memory.readPointer(methodptrarr.add(Process.pointerSize * i));
        var name = Memory.readUtf8String(method_getName(method));
        var imp = method_getImplementation(method);
		result.push({"name": "- " + name, "imp":imp});
        //console.log("-[" + classname + " " + name + "] -> " + imp);
    }
	Memory.writeU32(pcount, 0);
	methodptrarr = class_copyMethodList(metaclass_, pcount);
    count = Memory.readU32(pcount);
    for (var i = 0; i < count; i++) {
        var method = Memory.readPointer(methodptrarr.add(Process.pointerSize * i));
        var name = Memory.readUtf8String(method_getName(method));
        var imp = method_getImplementation(method);
		result.push({"name": "+ " + name, "imp":imp});
        //console.log("+[" + classname + " " + name + "] -> " + imp);
    }
	return result;
}

// 强制过证书校验
function forcetrustcert() {
	Interceptor.replace(Module.findExportByName(null, 'SecTrustEvaluate'),
		new NativeCallback(function (trust, result) {
			Memory.writePointer(result, ptr('0x1'));
			 console.log('pass SecTrustEvaluate');
			return 0;
		}, 'int', ['pointer', 'pointer'])
	);
	/* 获取app路径下的可执行模块 hook存在以下方法的类
		- evaluateServerTrust:forDomain:
		- allowInvalidCertificates
		- shouldContinueWithInvalidCertificate
	*/
	var apppath = Process.enumerateModulesSync()[0]['path'];
	apppath = apppath.slice(0, apppath.lastIndexOf('/'));
	getmodule().forEach(function (module, i) {
		if (module.indexOf(apppath) != 0) return;
		getmoduleclass(module).forEach(function (classname, j) {
			getclassmethod(classname).forEach(function (methodinfo, k) {
				var name = methodinfo['name'];
				if (name == '- evaluateServerTrust:forDomain:' ||
						name == '- allowInvalidCertificates' ||
						name == '- shouldContinueWithInvalidCertificate') {
					console.log("forcetrustcert " + classname + " " + name);
					Interceptor.attach(methodinfo['imp'], {
						onEnter: function (args) {
							console.log("forcetrustcert " + classname + " " + name);
						},
						onLeave: function (retval) {
							retval.replace(ptr('0x1'));
						}
					});
				}
			});
		});
	});
}

// 随机字符串
function randomString(len) {
　　len = len || 32;
　　var $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
　　var maxPos = $chars.length;
　　var pwd = '';
　　for (i = 0; i < len; i++) {
　　　　pwd += $chars.charAt(Math.floor(Math.random() * maxPos));
　　}
　　return pwd;
}

// 生成二进制NSData
function rawnsdata() {
	var buf = Memory.alloc(256);
	for (var i = 0; i < 256; i++) {
		Memory.writeU8(buf.add(i), i);
	}
	return ObjC.classes.NSData.dataWithBytes_length_(buf, 256);
}

function dump_alertview() {
    ObjC.chooseSync(ObjC.classes.UIAlertController).forEach(
        function(alertcontroller) {
            var actions = alertcontroller.actions();
            for (var i = 0; i < actions.count(); i++) {
                var action = actions.objectAtIndex_(i);
                var handler = action.handler();
                if (handler != null) handler = handler.handle;
                console.log(action.title(), handler);
            }
        }
    );
}

function get_object_method_address(object, action) {
    var class_getMethodImplementation = new NativeFunction(Module.findExportByName(null, "class_getMethodImplementation"), "pointer", ["pointer", "pointer"]);
    var imp = class_getMethodImplementation(object.class(), ObjC.selector(action));
    var mod = Process.getModuleByAddress(imp);
    return mod['name'] + '!' + imp.sub(mod['base'])
}   

function get_function_address(address) {
    address = ptr(address);
    var symbol = getaddressmodule(address);
    var sympath = symbol['fname'];
    var symname = sympath.split('/')[sympath.split('/').length - 1];
    return symname + '!' + address.sub(symbol['fbase']);
}

// 遍历界面元素
function tranverse_view() { 
    var appCls = ObjC.classes["NSApplication"] || ObjC.classes["UIApplication"];
    var mainwin = appCls.sharedApplication().keyWindow();
    var arr = Array();
    function find_subviews_internal(view, depth) {
        if (view == null) {
            return;
        }
        var space = '';
        for (var i = 0; i < depth; i++) {
            space += '-';
        }
        var text = '';
        var ctrlname = view.class().toString();
        if (view.isKindOfClass_(ObjC.classes.UILabel)) {
            text = view.text();
        }
        var responder = '';
        var iter = true;
        if (view.respondsToSelector_(ObjC.selector('allTargets'))) {
            var targets = view.allTargets().allObjects();
			if (targets != null) {
				var targetcount = targets.count();
				var events = view.allControlEvents();
				for (var i = 0; i < targetcount; i++) {
					var target = targets.objectAtIndex_(i);
					var actions = view.actionsForTarget_forControlEvent_(target, events);
					if (actions != null) {
						var actioncount = actions.count();
						for (var j = 0; j < actioncount; j++) {
                            var clsname = target.class().toString();
                            var action = actions.objectAtIndex_(j).toString();
                            var addr = get_object_method_address(target, action)
							responder += '[' + clsname + ' ' + action + ']=' + addr + ',';
						}
					}
				}
			}
        }
        var msg = space + ctrlname + " " + view.handle;
        if (text != '') {
            msg += "  => " + text;
        }
        if (responder != '') {
            msg += "  selectors= " + responder;
        }
        console.log(tounicode(msg));
        if (view.respondsToSelector_(ObjC.selector('actions'))) {
            // UIAlertView
            iter = false;
            var actions = view.actions();
            var actioncount = actions.count();
            for (var j = 0; j < actioncount; j++) {
                var action = actions.objectAtIndex_(j);
                var title = action.title().UTF8String();
                if (action.handler() == null) {
                    console.log(tounicode(space + '  action= ' + title));
                } else {
                    var block = action.handler().handle;
                    var funcaddr = Memory.readPointer(block.add(Process.pointerSize * 2));
                    var types = action.handler().types;
                    var addr = get_function_address(funcaddr);
                    console.log(tounicode(space + '  action= ' + title + ' ' + types + ' ' + addr));
                }
                
            }
        }
        if (view.respondsToSelector_(ObjC.selector('gestureRecognizers'))) {
            var gestures = view.gestureRecognizers();
            if (gestures != null) {
                var gesturecount = gestures.count();
                for (var k = 0; k < gesturecount; k++) {
                    var gesture = gestures.objectAtIndex_(k);
                    var targets = ObjC.Object(gesture.handle.add(16).readPointer());
                    if (targets.handle.isNull()) {
                        continue;
                    }
                    var targetcount = targets.count();
                    for (var l = 0; l < targetcount; l++) {
                        var target = targets.objectAtIndex_(l);
                        var addr = get_function_address(target.action());
                        console.log(space + 'action', addr);
                    }
                }
            }
            
            /*for (var j = 0; j < gesturecount; j++) {
                var gesture = gestures.objectAtIndex_(j);

            }*/
        }
        var subviews = view.subviews();
		if (subviews != null && iter) {
			var subviewcount = subviews.count();
			for (var i = 0; i < subviewcount; i++) {
				var subview = subviews.objectAtIndex_(i);
				find_subviews_internal(subview, depth + 1);
			}
		}
    }

    find_subviews_internal(mainwin, 0);
}

function trace_view() {
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication["- sendAction:to:from:forEvent:"].implementation, {
        onEnter:function(args) {
            var action = Memory.readUtf8String(args[2]);
            var toobj = ObjC.Object(args[3]);
            var fromobj = ObjC.Object(args[4]);
            var event = ObjC.Object(args[5]);
            console.log('SendAction:' + action + ' to:' + toobj.toString() + 
          ' from:' + fromobj.toString() + ' forEvent:' + event.toString() + ']');
        }
    });
}
