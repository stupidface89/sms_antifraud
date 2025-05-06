from api_master.device_build import DeviceBuild
from api_master.task import Task
from settings import logging_info


def uber_script(device_build: DeviceBuild, task: Task) -> str:

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

    mcc = task.mcc
    mnc = task.mnc
    country_code = task.country_code
    mcc_mnc = str(mcc) + str(mnc)

    script = ("""
            'use strict';
            setTimeout(function () {
                Java.perform(function() {
                    try{

                        let build = Java.use('android.os.Build');
                        let Wifi = Java.use("android.net.wifi.WifiInfo");
                        let TelephonyManager = Java.use('android.telephony.TelephonyManager')

                        TelephonyManager.getSimOperator.overload('int').implementation = function (val) {
                            console.log(this)
                            return 25507;
                        }

                        TelephonyManager.getSimCountryIso.overload('int').implementation = function (val) {
                            console.log(this)
                            return 'ua';
                        }

                        TelephonyManager.getPhoneType.overload('int').implementation = function(val) {
                            console.log(this)
                        }

                        TelephonyManager.getNetworkOperator.overload('int').implementation = function (val) {
                            console.log(this)
                            return 25507
                        }

                        Wifi.getMacAddress.implementation = function () {
                            var tmp = this.getMacAddress();
                            console.log("[*]real MAC: "+tmp);
                            return tmp;
                        }

                        // Делаем подмену параметров
                        build.FINGERPRINT.value = '%s';
                        build.MANUFACTURER.value = '%s';
                        build.MODEL.value = '%s';
                        build.PRODUCT.value = '%s';
                        build.BRAND.value = '%s';
                        build.HARDWARE.value = '%s';
                        build.DEVICE.value = '%s';
                        build.BOARD.value = '%s';
                        build.USER.value = '%s';
                        build.DISPLAY.value = '%s';
                        build.ID.value = '%s';
                        build.TYPE.value = '%s';
                        build.TAGS.value = '%s';
                        build.BOOTLOADER.value = '%s';
                        build.CPU_ABI.value = '%s';
                        build.CPU_ABI2.value = '%s';
                        build.HOST.value = '%s';

                        TelephonyManager.getSimOperator.overload('int').implementation = function (val) {
                            console.log('getSimOperator was call')
                            return %s;
                        }

                        TelephonyManager.getSimCountryIso.overload('int').implementation = function (val) {
                            console.log('getSimCountryIso was call')
                            return %s;
                        }

                        TelephonyManager.getNetworkOperator.overload('int').implementation = function (val) {
                            console.log('getNetworkOperator was call')
                            return %s;
                        }

        console.log(`
            [!] FINGERPRINT - ${build.FINGERPRINT.value},
            [!] MANUFACTURER - ${build.MANUFACTURER.value}, 
            [!] MODEL - ${build.MODEL.value},
            [!] PRODUCT - ${build.PRODUCT.value},
            [!] BRAND - ${build.BRAND.value},
            [!] HARDWARE - ${build.HARDWARE.value},
            [!] DEVICE - ${build.DEVICE.value},
            [!] BOARD - ${build.BOARD.value},
            [!] USER - ${build.USER.value},
            [!] DISPLAY - ${build.DISPLAY.value},
            [!] ID - ${build.ID.value} 
            [!] TYPE - ${build.TYPE.value} 
            [!] TAGS - ${build.TAGS.value} 
            [!] BOOTLOADER - ${build.BOOTLOADER.value}
            [!] CPU_ABI - ${build.CPU_ABI.value}
            [!] CPU_ABI2 - ${build.CPU_ABI2.value}
            [!] HOST - ${build.HOST.value}
        `)
                    }
                    catch(error){
                        console.log("[-] Error Detected");
                        console.log((error.stack));
                    }
            });
        }, 0);       
        """) % (fingerprint, manufacturer, retail_model, device, brand, hardware, device, board, user, display,
                firmware_id, user_type, tag, bootloader, cpu_abi, cpu_abi2, host, mcc_mnc, country_code, mcc_mnc)

    return script
