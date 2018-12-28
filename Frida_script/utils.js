/* JavaScript String -> NSString */
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

/* Get Objective-C Method of class */
function getclassmethod(cls) {
    var pcount = Memory.alloc(4);
    Memory.writeU32(pcount, 0);
    var class_copyMethodList = new NativeFunction(Module.findExportByName(null, "class_copyMethodList"), "pointer", ["pointer", "pointer"]);
    var method_getName = new NativeFunction(Module.findExportByName(null, "method_getName"), "pointer", ["pointer"]);
    var method_getImplementation = new NativeFunction(Module.findExportByName(null, "method_getImplementation"), "pointer", ["pointer"]);
    var methodptrarr = class_copyMethodList(cls.class().handle, pcount);
    var count = Memory.readU32(pcount);
    for (var i = 0; i < count; i++) {
        var method = Memory.readPointer(methodptrarr.add(Process.pointerSize * i));
        var name = Memory.readUtf8String(method_getName(method));
        var imp = method_getImplementation(method);
        console.log(name + " -> " + imp + "\n");
    }
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
	if (typeof(ObjC.classes.AFSecurityPolicy) !== 'undefined') {
		Interceptor.attach(ObjC.classes.AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation, {
			onEnter: function (args) {
				console.log('pass -[AFSecurityPolicy evaluateServerTrust:forDomain:]')
			},
			onLeave: function (retval) {
				retval.replace(ptr('0x1'));
			}
		});
		
		Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
			onEnter: function (args) {
				args[2] = ptr('0x1');
				console.log('pass -[AFSecurityPolicy setAllowInvalidCertificates:]')
			},
			onLeave: function (retval) {
			}
		});
		Interceptor.attach(ObjC.classes.AFSecurityPolicy['- allowInvalidCertificates'].implementation, {
			onEnter: function (args) {
				console.log('pass -[AFSecurityPolicy setAllowInvalidCertificates:]')
			},
			onLeave: function (retval) {
				retval.replace(ptr('0x1'));
			}
		});
	};
	if (typeof(ObjC.classes.MKNetworkOperation) !== 'undefined') {
		Interceptor.attach(ObjC.classes.MKNetworkOperation['- setShouldContinueWithInvalidCertificate:'].implementation, {
			onEnter: function (args) {
				args[2] = ptr('0x1');
				console.log('pass -[MKNetworkOperation setShouldContinueWithInvalidCertificate:]')
			},
			onLeave: function (retval) {
			}
		});	
		Interceptor.attach(ObjC.classes.MKNetworkOperation['- shouldContinueWithInvalidCertificate'].implementation, {
			onEnter: function (args) {
				console.log('pass -[MKNetworkOperation shouldContinueWithInvalidCertificate]')
			},
			onLeave: function (retval) {
				retval.replace(ptr('0x1'));
			}
		});
	}
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
