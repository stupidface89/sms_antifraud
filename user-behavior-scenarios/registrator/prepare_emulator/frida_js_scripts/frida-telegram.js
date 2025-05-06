'use strict';

Java.perform(function() {
    try{
        // Включаем логи в глобальных переменных приложения
        let build_vars = Java.use('org.telegram.messenger.BuildVars');

        build_vars.LOGS_ENABLED.value = true;
        console.log('\n[+] Enabled logs - ', build_vars.LOGS_ENABLED.value)

        let EmuDetector = Java.use('org.telegram.messenger.EmuDetector');
        EmuDetector.detect.implementation = function () {
            console.log('[!] Emulator Detector was call.', 'We catch that and return False instead ', this.detect());
            return false;
        }

        EmuDetector.isCheckTelephony.implementation = function(){
            console.log('isCheckTelephony is called');
            let ret = this.isCheckTelephony();
            console.log('isCheckTelephony ret value is ' + ret);
            return ret;
        };

        EmuDetector.checkBasic.implementation = function(){
            console.log('checkBasic is called');
            let ret = this.checkBasic();
            console.log('checkBasic ret value is ' + ret);
            return ret;
        };

        EmuDetector.checkAdvanced.implementation = function(){
            console.log('checkAdvanced is called');
            let ret = this.checkAdvanced();
            console.log('checkAdvanced ret value is ' + ret);
            return ret;
        };

        EmuDetector.checkPhoneNumber.implementation = function(){
            console.log('checkPhoneNumber is called');
            let ret = this.checkPhoneNumber();
            console.log('checkPhoneNumber ret value is ' + ret);
            return ret;
        };

        EmuDetector.checkTelephony.implementation = function(){
            console.log('checkTelephony is called');
            let ret = this.checkTelephony();
            console.log('checkTelephony ret value is ' + ret);
            return ret;
        };

        EmuDetector.checkOperatorNameAndroid.implementation = function(){
            console.log('checkOperatorNameAndroid is called');
            let ret = this.checkOperatorNameAndroid();
            console.log('checkOperatorNameAndroid ret value is ' + ret);
            return ret;
        };

        EmuDetector.checkQEmuDrivers.implementation = function(){
            console.log('checkQEmuDrivers is called');
            let ret = this.checkQEmuDrivers();
            console.log('checkQEmuDrivers ret value is ' + ret);
            return ret;
        };

        EmuDetector.checkFiles.implementation = function(strArr, emulatorTypes){
            console.log('checkFiles is called');
            let ret = this.checkFiles(strArr, emulatorTypes);
            console.log('checkFiles ret value is ' + ret);
            return ret;
        };

        EmuDetector.getProp.implementation = function(context, str){
            console.log('getProp is called');
            let ret = this.getProp(context, str);
            console.log('getProp ret value is ', context, str);
            return ret;
        };

        EmuDetector.checkQEmuProps.implementation = function(){
            console.log('checkQEmuProps is called');
            let ret = this.checkQEmuProps();
            console.log('checkQEmuProps ret value is ' + ret);
            return ret;
        };

        EmuDetector.checkIp.implementation = function(){
            console.log('checkIp is called');
            let ret = this.checkIp();
            console.log('checkIp ret value is ' + ret);
            return ret;
        };


        EmuDetector.isSupportTelePhony.implementation = function(){
            console.log('isSupportTelePhony is called');
            let ret = this.isSupportTelePhony();
            console.log('isSupportTelePhony ret value is ' + ret);
            return ret;
        };


        let Build = Java.use('android.os.Build');
        let Version = Java.use('android.os.Build$VERSION');

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
        Build.IS_EMULATOR.value = false
        Version.INCREMENTAL.value = '420126702'

        console.log('INCREMENTAL', Version.INCREMENTAL.value)
        console.log('SERIAL', Version.RELEASE.value)
        console.log('----', Build.FINGERPRINT.value)

    }
    catch(error){
        console.log("[-] Error Detected");
        console.log((error.stack));
    }
});