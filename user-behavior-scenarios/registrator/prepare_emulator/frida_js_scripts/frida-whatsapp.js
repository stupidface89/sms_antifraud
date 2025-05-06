'use strict';

var RANDOM = function() {};

function _randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function _randomHex(len) {
    var hex = '0123456789abcdef';
    var output = '';
    for (var i = 0; i < len; ++i) {
        output += hex.charAt(Math.floor(Math.random() * hex.length));
    }
    return output;
}

function _pad(n, width) {
    n = n + "";
    return n.length >= width ? n : new Array(width - n.length + 1).join("0") + n;
}

function _randomPaddedInt(length) {
    return _pad(_randomInt(0, Math.pow(10, length)), length);
}

function _luhn_getcheck(code) {
    code = String(code).concat("0");
    var len = code.length;
    var parity = len % 2;
    var sum = 0;
    for (var i = len - 1; i >= 0; i--) {
        var d = parseInt(code.charAt(i))
        if (i % 2 == parity) {
            d *= 2;
        }
        if (d > 9) {
            d -= 9;
        }
        sum += d;
    }
    var checksum = sum % 10;
    return checksum == 0 ? 0 : 10 - checksum;
}

function _luhn_verify(code) {
    code = String(code);
    var len = code.length;
    var parity = len % 2;
    var sum = 0;
    for (var i = len - 1; i >= 0; i--) {
        var d = parseInt(code.charAt(i))
        if (i % 2 == parity) {
            d *= 2;
        }
        if (d > 9) {
            d -= 9;
        }
        sum += d;
    }
    return sum % 10 == 0;
}

/* Spoofing functions */

function spoofAndroidID(android_id) {
    if (android_id == RANDOM) {
        android_id = _randomHex(16);
    } else if (android_id !== null) {
        android_id = String(android_id).toLowerCase();
        if (! android_id.match(/^[0-9a-f]{16}$/)) {
            throw new Error("Invalid Android ID value");
        }
    }

    var ss = Java.use("android.provider.Settings$Secure");
    ss.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function(context, param) {
        if (param == ss.ANDROID_ID.value) {
            return android_id;
        } else {
            return this.getString(context, param);
        }
    }
}

function spoofPhone(phone) {
    if (phone === RANDOM) {
        phone = _randomPaddedInt(10);
    } else if (phone !== null) {
        phone = String(phone);
        if (! phone.match(/^[0-9]{1,15}$/)) {
            throw new Error("Invalid phone number");
        }
    }
    var tm = Java.use("android.telephony.TelephonyManager");
    tm.getLine1Number.overload().implementation = function() {
        return phone;
    }
}

function spoofIMEI(imei) {
    if (imei === RANDOM) {
        imei = _randomPaddedInt(14);
        imei = imei.concat(_luhn_getcheck(imei));
    } else if (imei !== null) {
        imei = String(imei);
        if (! imei.match(/^[0-9]{15}$/)) {
            throw new Error("Invalid IMEI value");
        }
        if (! _luhn_verify(imei)) {
            console.warn("IMEI has an invalid check digit");
        }
    }
    var tm = Java.use("android.telephony.TelephonyManager");
    tm.getDeviceId.overload().implementation = function() {
        return imei;
    }
    tm.getDeviceId.overload("int").implementation = function(slotIndex) {
        return imei;
    }
    tm.getImei.overload().implementation = function() {
        return imei;
    }
    tm.getImei.overload("int").implementation = function(slotIndex) {
        return imei;
    }
}

function spoofIMSI(imsi) {
    if (imsi == RANDOM) {
        imsi = _randomPaddedInt(15);
    } else if (imsi !== null) {
        imsi = String(imsi);
        if (! imsi.match(/^[0-9]{14,15}$/)) {
            throw new Error("Invalid IMSI value");
        }
    }
    var tm = Java.use("android.telephony.TelephonyManager");
    tm.getSubscriberId.overload().implementation = function() {
        return imsi;
    }
}

function spoofICCID(iccid) {
    if (iccid == RANDOM) {
        iccid = "89".concat(_randomPaddedInt(16));
        iccid = iccid.concat(_luhn_getcheck(iccid));
    } else if (iccid !== null) {
        iccid = String(iccid);
        if (! iccid.match(/^[0-9]{19,20}$/)) {
            throw new Error("Invalid ICCID value");
        }
        if (! _luhn_verify(iccid)) {
            console.warn("ICCID has an invalid check digit");
        }
    }
    var tm = Java.use("android.telephony.TelephonyManager");
    tm.getSimSerialNumber.overload().implementation = function() {
        return iccid;
    }
}

function spoofMAC(mac) {
    if (mac == RANDOM) {
        mac = [];
        for (var i = 0; i < 6; i++) {
            mac.push(_randomInt(0, 255));
        }
        mac = Java.array("byte", mac);
    } else if (mac !== null) {
        var mac_str = String(mac).toUpperCase();
        if (! mac_str.match(/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/)) {
            throw new Error("Invalid MAC address value");
        }
        mac = [];
        var mac_arr = mac_str.split(":");
        for (var i = 0; i < 6; i++) {
            mac.push(parseInt(mac_arr[i], 16));
        }
        mac = Java.array("byte", mac);
    }
    var ni = Java.use("java.net.NetworkInterface");
    ni.getHardwareAddress.overload().implementation = function() {
        return mac;
    }
}

function hideGSFID(gsf_id) {
    var cr = Java.use("android.content.ContentResolver");
    cr.query.overload("android.net.Uri", "[Ljava.lang.String;", "android.os.Bundle", "android.os.CancellationSignal").implementation = function(uri, projection, queryArgs, cancellationSignal) {
        var qres = this.query(uri, projection, queryArgs, cancellationSignal);
        if (uri.toString() == "content://com.google.android.gsf.gservices") {
            qres = null;
        }
        return qres;
    }
    cr.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "android.os.CancellationSignal").implementation = function(uri, projection, selection, selectionArgs, sortOrder, cancellationSignal) {
        var qres = this.query(uri, projection, selection, selectionArgs, sortOrder, cancellationSignal);
        if (uri.toString() == "content://com.google.android.gsf.gservices") {
            qres = null;
        }
        return qres;
    }
    cr.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
        var qres = this.query(uri, projection, selection, selectionArgs, sortOrder);
        if (uri.toString() == "content://com.google.android.gsf.gservices") {
            qres = null;
        }
        return qres;
    }
}

Java.perform(function () {
    spoofMAC(RANDOM);
    spoofICCID(RANDOM);
    spoofIMSI(RANDOM);
    spoofAndroidID(RANDOM);
    spoofIMEI(RANDOM);
    spoofPhone(RANDOM);
    hideGSFID();

    let TelephonyManager = Java.use('android.telephony.TelephonyManager');
        let String = Java.use('java.lang.String')

        console.log('\n -------------------')

        TelephonyManager.getDeviceId.overload('int').implementation = function(val1) {
            console.log('Device ID - ', this.getDeviceId(val1), val1)
            return this.getDeviceId(val1)
        }
        TelephonyManager.getLine1Number.overload('int').implementation = function(val1) {
            console.log('Line1 Number - ', this.getLine1Number(val1), val1 )
            return this.getLine1Number(val1)
        }

        TelephonyManager.getNetworkCountryIso.overload('int').implementation = function (val1) {
            console.log('NetworkCountry ISO - ', this.getNetworkCountryIso(val1), val1)
            return this.getNetworkCountryIso(val1)
        }

        TelephonyManager.getNetworkType.overload('int').implementation = function (val1) {
            console.log('NetworkType - ', this.getNetworkType(val1), val1)
            return this.getNetworkType(val1)
        }

        TelephonyManager.getNetworkOperator.overload('int').implementation = function (val1) {
            console.log('NetworkOperator - ', this.getNetworkOperator(val1), val1)
            return 25507
        }

        TelephonyManager.getNetworkOperatorName.overload('int').implementation = function(val1) {
            console.log('Network Operator Name - ', val1)
            return this.getNetworkOperatorName(val1)
        }

        TelephonyManager.getPhoneType.overload('int').implementation = function(val1) {
            console.log('Phone Type - ', this.getPhoneType(val1), val1)
            return this.getPhoneType(val1)
        }

        TelephonyManager.getSimCountryIso.overload('int').implementation = function (val1) {
            console.log('Sim Country ISO - ', this.getSimCountryIso(val1))
            return 'ua';
        }

        TelephonyManager.getSimSerialNumber.overload('int').implementation = function (val1) {
            console.log('Sim Serial Number - ', this.getSimSerialNumber(val1))
            return 25507;
        }

        TelephonyManager.getSubscriberId.overload('int').implementation = function (val1) {
            console.log('Subscriber ID - ', this.getSubscriberId(val1))
            return 25507;
        }

        TelephonyManager.getSimOperator.overload('int').implementation = function (val1) {
            console.log('Sim Operator - ', this.getSimOperator(val1))
            return 25507;
        }

        let Locale = Java.use('java.util.Locale')
        Locale.getLanguage.implementation = function() {
            return String.$new('ua')
        }

        console.log('Locale', Locale.getDefault())
        console.log('Language', Locale.getDefault().getLanguage())

        //Делаем подмену параметров
        let Build = Java.use('android.os.Build');

        console.log('Build.RADIO - ', Build.RADIO.value)
        Build.FINGERPRINT.value = 'zte/p809t70/p809t70:10/QD1A.190821.011.C4/420126702:user/release-keys';
        Build.MANUFACTURER.value = 'ZTE';
        Build.MODEL.value = 'TURKCELL T70';
        Build.PRODUCT.value = 'P809T70';
        Build.BRAND.value = 'zte';
        Build.HARDWARE.value = 'Kirin 955';
        Build.DEVICE.value = 'P809T70';
        Build.BOARD.value = 'Kirin 955';
        Build.USER.value = 'P809T70-user';
        Build.DISPLAY.value = 'P809T70-user 10 QD1A.190821.011.C4 release-keys';
        Build.ID.value = 'QD1A.190821.011.C4';
        Build.TYPE.value = 'user';
        Build.TAGS.value = 'release-keys';
        Build.BOOTLOADER.value = 'unknown';
        Build.CPU_ABI.value = 'arm64-v8a';
        Build.CPU_ABI2.value = '';
        Build.HOST.value = 'h8.zte-ddp-ru.org';


        let Version = Java.use('android.os.Build$VERSION');


        console.log(Build.MANUFACTURER.value + Build.MODEL.value)

        let SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(var1, var2) {
            if(!var1.includes('debug.sqlite')){
                console.log('[*] System Properties was call: ', var1, var2)
            }
            return this.get(var1, var2)
        }


    let C0AX = Java.use("X.0AX");
    C0AX.get.implementation = function(){
        console.log('get is called');
        let ret = this.get();
        console.log('get ret value is ' + ret);
        return ret;
    };

    let C002501d = Java.use("X.01d");
    C002501d.A00.implementation = function(){
        console.log('A00 is called');
        let ret = this.A00();
        console.log('A00 ret value is ' + ret);
        return ret;
    };

    C002501d.A09.implementation = function(){
        console.log('A09 is called');
        let ret = this.A09();
        console.log('A09 ret value is ' + ret);
        return ret;
    };

    C002501d.A0A.implementation = function(context, str, bArr){
        console.log('A0A is called');
        let ret = this.A0A(context, str, bArr);
        console.log('A0A ret value is ' + ret);
        return ret;
    };

});

