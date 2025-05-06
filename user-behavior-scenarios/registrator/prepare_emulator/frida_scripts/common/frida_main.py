from api_master.device_build import DeviceBuild
from api_master.task import Task


def telephony_identifier_script(task):
    """
        Взаимодействуем с библиотекой android.telephony.TelephonyManager для подмены mcc и mnc
    """
    mcc = task.mcc
    mnc = task.mnc
    country_code = task.country_code

    mcc_mnc = str(mcc) + str(mnc)

    script = """
    Java.perform(function() {
        let TelephonyManager = Java.use('android.telephony.TelephonyManager')
    
        TelephonyManager.getSimOperator.overload('int').implementation = function (val) {
            console.log(this.getSimOperator())
            return '%s';
        }
    
        TelephonyManager.getSimCountryIso.overload('int').implementation = function (val) {
            console.log(this.getSimCountryIso())
            return '%s';
        }
    
        TelephonyManager.getPhoneType.overload('int').implementation = function(val) {
            console.log(this.getPhoneType())
            return this.getPhoneType()
        }
    
        TelephonyManager.getNetworkOperator.overload('int').implementation = function (val) {
            console.log(this.getNetworkOperator())
            return '%s';
        }
    });
    """ % (mcc_mnc, country_code, mcc_mnc)
    return script


def android_identifies_script():
    script = """
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
            });
    """
    return script


def build_identifies_script(device_build: DeviceBuild, task: Task) -> str:
    fingerprint = device_build.fingerprint
    manufacturer = device_build.manufacturer
    retail_model = device_build.retail_model
    device = device_build.device
    display = device_build.display
    brand = device_build.brand
    hardware = device_build.hardware
    board = device_build.board
    user = device_build.user
    firmware_id = device_build.id
    user_type = device_build.type
    tag = device_build.tags
    bootloader = device_build.bootloader
    cpu_abi = device_build.cpu_abi
    cpu_abi2 = device_build.cpu_abi2
    host = device_build.host
    version_incremental = device_build.version_incremental

    script = ("""
            'use strict';
            setTimeout(function () {
                Java.perform(function() {
                    try{
                        
                        // Проверяем вызов SystemProperties
                        let SystemProperties = Java.use('android.os.SystemProperties');
                        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(var1, var2) {
                            if(!var1.includes('debug.sqlite')){
                                console.log('[*] System Properties was call: ', var1, var2)
                                console.log('var1:', var1, 'var2:', var2)
                            } 
                            return this.get(var1, var2)
                        }
                    
                    
                        let Build = Java.use('android.os.Build');
                        let Version = Java.use('android.os.Build$VERSION');
                        
                        // Делаем подмену параметров
                        Build.FINGERPRINT.value = '%s';
                        Build.MANUFACTURER.value = '%s';
                        Build.MODEL.value = '%s';
                        Build.PRODUCT.value = '%s';
                        Build.BRAND.value = '%s';
                        Build.HARDWARE.value = '%s';
                        Build.DEVICE.value = '%s';
                        Build.BOARD.value = '%s';
                        Build.USER.value = '%s';
                        Build.DISPLAY.value = '%s';
                        Build.ID.value = '%s';
                        Build.TYPE.value = '%s';
                        Build.TAGS.value = '%s';
                        Build.BOOTLOADER.value = '%s';
                        Build.CPU_ABI.value = '%s';
                        Build.CPU_ABI2.value = '%s';
                        Build.HOST.value = '%s';
                        Build.IS_EMULATOR.value = false;
                        Version.INCREMENTAL.value = '%s';
                    
    console.log(`
    [!] FINGERPRINT - ${Build.FINGERPRINT.value},
    [!] MANUFACTURER - ${Build.MANUFACTURER.value}, 
    [!] MODEL - ${Build.MODEL.value},
    [!] PRODUCT - ${Build.PRODUCT.value},
    [!] BRAND - ${Build.BRAND.value},
    [!] HARDWARE - ${Build.HARDWARE.value},
    [!] DEVICE - ${Build.DEVICE.value},
    [!] BOARD - ${Build.BOARD.value},
    [!] USER - ${Build.USER.value},
    [!] DISPLAY - ${Build.DISPLAY.value},
    [!] ID - ${Build.ID.value} 
    [!] TYPE - ${Build.TYPE.value} 
    [!] TAGS - ${Build.TAGS.value} 
    [!] BOOTLOADER - ${Build.BOOTLOADER.value}
    [!] CPU_ABI - ${Build.CPU_ABI.value}
    [!] CPU_ABI2 - ${Build.CPU_ABI2.value}
    [!] HOST - ${Build.HOST.value}
    `)
                    }
                    catch(error){
                        console.log("[-] Error Detected");
                        console.log((error.stack));
                    }
            });
        }, 3500);       
        """) % (fingerprint, manufacturer, retail_model, device, brand, hardware, device, board, user, display,
                firmware_id, user_type, tag, bootloader, cpu_abi, cpu_abi2, host, version_incremental)

    return script
