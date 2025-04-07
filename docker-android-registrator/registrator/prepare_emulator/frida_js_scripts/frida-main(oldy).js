'use strict';

// ------------------ SSL bypass -------------------
setTimeout(function () {
    Java.perform(function () {


// ---------------- Crypto ----------------
//
//        function bin2ascii(array) {
//            var result = [];
//
//            for (var i = 0; i < array.length; ++i) {
//                result.push(String.fromCharCode( // hex2ascii part
//                    parseInt(
//                        ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
//                        16
//                    )
//                ));
//            }
//            return result.join('');
//        }
//
//        function bin2hex(array, length) {
//            var result = "";
//
//            length = length || array.length;
//
//            for (var i = 0; i < length; ++i) {
//                result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
//            }
//            return result;
//        }
//
//        Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B', 'java.lang.String').implementation = function(key, spec) {
//            send("KEY: " + bin2hex(key) + " | " + bin2ascii(key));
//            return this.$init(key, spec);
//        };
//
//        Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String').implementation = function(spec) {
//            send("CIPHER: " + spec);
//            return this.getInstance(spec);
//        };
//
//        Java.use('javax.crypto.Cipher')['doFinal'].overload('[B').implementation = function(data) {
//            send("doFinal!");
//            send(bin2ascii(data));
//            return this.doFinal(data);
//        };
//    });


// END ---------------- Crypto ----------------

// ----------------- TELEPHONY MANAGER -----------------



            //Делаем подмену параметров
            let Build = Java.use('android.os.Build');

            console.log("\x1b[31m", Build.FINGERPRINT.value,"\x1b[0m")
            Build.FINGERPRINT.value= String.$new('zte/p809t70/p809t70:10/QD1A.190821.011.C4/420126702:user/release-keys');
            Build.MANUFACTURER.value = 'ZTE';
            Build.MODEL.value = 'TURKCELL T70';
            Build.PRODUCT.value = 'P809T70';
            Build.BRAND.value = 'zte';

            Build.FINGERPRINT.value = String.$new('zte/p809t70/p809t70:10/QD1A.190821.011.C4/420126702:user/release-keys');
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

            let Version = Java.use('android.os.Build$VERSION');
            let VersionItem = Version.$new();
            VersionItem.INCREMENTAL.value = '420126702';

            console.log('\x1b[2m[*] FINGERPRINT ->\x1b[0m \x1b[34;1m', Build.FINGERPRINT.value, '\x1b[0m');
            console.log('\x1b[2m[*] MANUFACTURER ->\x1b[0m\x1b[34;1m', Build.MANUFACTURER.value, '\x1b[0m');
            console.log('\x1b[2m[*] MODEL ->\x1b[0m\x1b[34;1m', Build.MODEL.value, '\x1b[0m');
            console.log('\x1b[2m[*] PRODUCT -> \x1b[0m\x1b[34;1m', Build.PRODUCT.value, '\x1b[0m');
            console.log('\x1b[2m[*] BRAND -> \x1b[0m\x1b[34;1m', Build.BRAND.value, '\x1b[0m');
            console.log('\x1b[2m[*] HARDWARE -> \x1b[0m\x1b[34;1m', Build.HARDWARE.value, '\x1b[0m');
            console.log('\x1b[2m[*] DEVICE -> \x1b[0m\x1b[34;1m', Build.DEVICE.value, '\x1b[0m');
            console.log('\x1b[2m[*] BOARD -> \x1b[0m\x1b[34;1m', Build.BOARD.value, '\x1b[0m');
            console.log('\x1b[2m[*] USER -> \x1b[0m\x1b[34;1m', Build.USER.value, '\x1b[0m');
            console.log('\x1b[2m[*] DISPLAY -> \x1b[0m\x1b[34;1m', Build.DISPLAY.value, '\x1b[0m');
            console.log('\x1b[2m[*] ID -> \x1b[0m\x1b[34;1m', Build.ID.value, '\x1b[0m');
            console.log('\x1b[2m[*] TYPE -> \x1b[0m\x1b[34;1m', Build.TYPE.value, '\x1b[0m');
            console.log('\x1b[2m[*] TAGS -> \x1b[0m\x1b[34;1m', Build.TAGS.value, '\x1b[0m');
            console.log('\x1b[2m[*] BOOTLOADER -> \x1b[0m\x1b[34;1m', Build.BOOTLOADER.value, '\x1b[0m');
            console.log('\x1b[2m[*] CPU_ABI -> \x1b[0m\x1b[34;1m', Build.CPU_ABI.value, '\x1b[0m');
            console.log('\x1b[2m[*] CPU_ABI2 -> \x1b[0m\x1b[34;1m', Build.CPU_ABI2.value, '\x1b[0m');

            console.log('\x1b[2m[*] INCREMENTAL -> \x1b[0m\x1b[34;1m', VersionItem.INCREMENTAL.value, '\x1b[0m')
            console.log('SERIAL', Version.RELEASE.value)

// ---------------- END TELEPHONY MANAGER ------------------

// ------------------- ZENLY ------------------

            // f*ing Sentry block requests
//            let HttpURLConnection = Java.use('java.net.HttpURLConnection')
//            let SentryHttpConnection = Java.use("io.sentry.transport.HttpConnection");
//            let URL = Java.use(('java.net.URL'));
//            SentryHttpConnection.createConnection.implementation = function(){
//                let some_url = URL.$new('some-origin')
//                let request = HttpURLConnection.$new(some_url)
//
//                console.log('createConnection is called');
//                let ret = this.createConnection();
//                console.log('createConnection ret value is ' + ret);
//                return request
//            };
//
//            let b = Java.use("com.amplitude.api.g$b");
//            b.x.implementation = function(){
//                console.log('x is called');
//                let ret = this.x();
//                console.log('x ret value is ' + ret);
//                return ret;
//            };
//
//            let c = Java.use("com.amplitude.api.c");
//            c.$init.overload('java.lang.String').implementation = function(str){
//                console.log('$init is called');
//                console.log('$init ret value is ', str);
//            };
//
//            let e = Java.use("com.amplitude.api.e");
//            e.c.implementation = function(aVar){
//                console.log('c is called');
//                console.log('c ret value is ', aVar.value);
//            };
//
//            // Zenly emudetect by Build's params should return True if we want to will be hide
//            let a = Java.use("ud0.a");
//            a.f.implementation = function(){
//                console.log('f is called');
//                console.log('f ret value is ' + ret);
//                return Java.use(android.lang.Boolean).$new('true')
//            };
//
//            // Блокируем запросы Appsflyer
//            let AFDeepLinkManager = Java.use("com.appsflyer.AFDeepLinkManager");
//            AFDeepLinkManager.ι.overload('android.content.Context', 'java.util.Map', 'android.net.Uri').implementation = function(context, map, uri){
//                console.log('ι is called');
//            };
//
//            let OneLinkHttpTask = Java.use("com.appsflyer.OneLinkHttpTask");
//            OneLinkHttpTask.doRequest.implementation = function(){
//                console.log('doRequest is called');
//                console.log('doRequest ret value is ' + ret);
//            };

            // END --------------- ZENLY ---------------

        }

        catch(error){
            console.log("[-] Error Detected");
            console.log((error.stack));
        }

    });




// ----------- Signal -----------
//    Java.perform(function() {
//
//        let ServiceResponse = Java.use('org.whispersystems.signalservice.internal.ServiceResponseProcessor')
//        let Response = Java.use("org.whispersystems.signalservice.internal.ServiceResponse");
//        let PushServiceSocket = Java.use('org.whispersystems.signalservice.internal.push.PushServiceSocket')
//        let RequestVerification = Java.use('org.whispersystems.signalservice.internal.push.RequestVerificationCodeResponse');
//
//
//        let AccountValues = Java.use("org.thoughtcrime.securesms.keyvalue.AccountValues");
//        let accountValue = AccountValues.$new.overload('org.thoughtcrime.securesms.keyvalue.KeyValueStore')
//
//
//        let ApplicationContext = Java.use("org.thoughtcrime.securesms.ApplicationContext");
//        ApplicationContext.initializeFcmCheck.implementation = function(){
//            console.log('initializeFcmCheck is called');
//            let ret = this.initializeFcmCheck();
//            console.log('initializeFcmCheck ret value is ' + ret);
//            return ret;
//        };
//
//        AccountValues.getFcmToken.implementation = function(){
//            console.log('getFcmToken is called');
//            let ret = this.getFcmToken();
//            console.log('getFcmToken ret value is ' + ret);
//            return ret;
//        };
//
//        Response.getStatus.implementation = function() {
//            let status = this.getStatus();
//            console.log('\x1b[34m[*] Response status - ', status, '\x1b[0m')
//            return status
//        }
//
//        ServiceResponse.captchaRequired.implementation = function() {
//            console.log('\x1b[31m[*] Captcha Required is -', this.captchaRequired(), '\x1b[0m')
//            return false
//        }
//
//        RequestVerification.getFcmToken.implementation = function() {
//            console.log('\x1b[34m[!] Retrieve FcmToken: ', this.getFcmToken(), '\x1b[0m')
//            return this.getFcmToken();
//        }
//
//        PushServiceSocket.requestPushChallenge.overload('java.lang.String', 'java.lang.String').implementation = function(val1, val2) {
//            console.log('\x1b[34m[*] Request Push Challenge ', val1, val2, '\x1b[0m');
//            return this.requestPushChallenge(val1, val2);
//        }
//
//        PushServiceSocket.requestPushChallenge.implementation = function(str, str2){
//            console.log('requestPushChallenge is called - ', str, str2 );
//            let ret = this.requestPushChallenge(str, str2);
//
//            console.log('requestPushChallenge value is ' + str, str2);
//            return ret;
//        };
//
//        let Request = Java.use("org.thoughtcrime.securesms.registration.PushChallengeRequest$Request");
//        Request.requestAndReceiveChallengeBlocking.implementation = function(){
//            console.log('requestAndReceiveChallengeBlocking is called');
//            let ret = this.requestAndReceiveChallengeBlocking();
//            console.log('requestAndReceiveChallengeBlocking ret value is ' + ret);
//            return ret;
//        };
//
//        let SignalServiceAccountManager = Java.use("org.whispersystems.signalservice.api.SignalServiceAccountManager");
//        SignalServiceAccountManager.requestRegistrationPushChallenge.implementation = function(str, str2){
//            console.log('requestRegistrationPushChallenge is called', str, str2);
//            let ret = this.requestRegistrationPushChallenge(str, str2);
//            console.log('requestRegistrationPushChallenge return value is ' + ret);
//            return ret;
//        };
//
//        PushServiceSocket.makeServiceRequest.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.util.Map', 'org.whispersystems.signalservice.internal.push.PushServiceSocket$ResponseCodeHandler', 'j$.util.Optional').implementation = function(str, str2, str3, map, responseCodeHandler, optional){
//            console.log('makeServiceRequest is called: ', str, str2, str3, map.value, responseCodeHandler.value, optional);
//            let ret = this.makeServiceRequest(str, str2, str3, map, responseCodeHandler, optional);
//            console.log('makeServiceRequest return value is ' + ret);
//            return ret;
//        };
//
//        // Handle
//        let EnterPhoneNumberFragment = Java.use("org.thoughtcrime.securesms.registration.fragments.EnterPhoneNumberFragment");
//        EnterPhoneNumberFragment.handleRequestVerification.implementation = function(context, z){
//            console.log('handleRequestVerification is called', context, z);
//            let ret = this.handleRequestVerification(context, z);
//            console.log('handleRequestVerification return value is ' + ret);
//            return ret;
//        };
//
//        // ### Try check why did not come FCM token
//        let VerifyAccountRepository = Java.use("org.thoughtcrime.securesms.registration.VerifyAccountRepository");
//        VerifyAccountRepository.requestVerificationCode.implementation = function(e164, password, mode, str){
//            console.log('requestVerificationCode is called', e164, password, mode, str);
//            let ret = this.requestVerificationCode(e164, password, mode, str);
//            console.log('requestVerificationCode return value is ' + ret);
//            return ret;
//        };
//
//        VerifyAccountRepository.PUSH_REQUEST_TIMEOUT.value = 20000
//
//
//        let PushChallengeRequest = Java.use("org.thoughtcrime.securesms.registration.PushChallengeRequest");
//        PushChallengeRequest.getPushChallengeBlocking.implementation = function(signalServiceAccountManager, optional, str, j){
//            console.log('getPushChallengeBlocking is called', signalServiceAccountManager, optional, str, j);
//            let ret = this.getPushChallengeBlocking(signalServiceAccountManager, optional, str, j);
//            console.log('getPushChallengeBlocking return value is ' + ret);
//            return ret;
//        };
//
//        let RegistrationData = Java.use("org.thoughtcrime.securesms.registration.RegistrationData");
//
//
//        // MCC + MNC
//        let CctTransportBackend = Java.use("com.google.android.datatransport.cct.CctTransportBackend");
//        CctTransportBackend.doSend.implementation = function(httpRequest){
//            console.log('doSend is called');
//            let ret = this.doSend(httpRequest);
//            console.log('doSend ret value is ' + ret);
//            return ret;
//        };
//
//        let FcmReceiveService = Java.use("org.thoughtcrime.securesms.gcm.FcmReceiveService");
//        FcmReceiveService.onMessageReceived.implementation = function(remoteMessage){
//            console.log('onMessageReceived is called');
//            let ret = this.onMessageReceived(remoteMessage);
//            console.log('onMessageReceived ret value is ' + ret);
//            return ret;
//        };
//
//
//
//        // Logs reading
//
//        let Log = Java.use("org.signal.core.util.logging.Log");
//
//        Log.w.overload('java.lang.String', 'java.lang.String').implementation = function(str, str2){
//            console.log('\x1b[35m Log.w', str,str2, '\x1b[0m');
//            let ret = this.w(str, str2);
//            return ret;
//        };
//
//        Log.i.overload('java.lang.String', 'java.lang.String').implementation = function(str, str2){
//            console.log('\x1b[35m Log.i', str, str2, '\x1b[0m');
//            let ret = this.i(str, str2);
//            return ret;
//        };
//
//        Log.tag.overload('java.lang.Class').implementation = function(str){
//            console.log('\x1b[35m Log.tag', str, '\x1b[0m');
//            let ret = this.tag(str);
//            return ret;
//        };
//
//        Log.d.overload('java.lang.String', 'java.lang.String').implementation = function(str, str2){
//            console.log('\x1b[35m Log.d', str, str2, '\x1b[0m');
//            let ret = this.i(str, str2);
//            return ret;
//        };
//    });
    // ---------- IMO -------------
//    let b = Java.use("com.proxy.ad.j.b");
//
//    b.b.implementation = function(){
//        console.log('b is called');
//        let ret = this.b();
//        console.log('b ret value is ' + ret);
//        return ret;
//    };
//
//    let c = Java.use("com.proxy.ad.adsdk.c.a.c");
//    c.a.implementation = function(){
//        console.log('a is called');
//        let ret = this.a();
//        console.log('a ret value is ' + ret);
//        return ret;
//    };
//
//    Java.choose("com.proxy.ad.adsdk.d.e", {
//        onMatch: function(instance){
//            console.log('[!] Class instance is loaded', instance)
//            instance.country = 'UA'
//        },
//        onComplete: function(){}
//    });

        // Глушим запрос аналитики api.likee.video
        let h = Java.use("c.a.a.a.i.h");
        h.run.overload().implementation = function(){
            console.log('api.likee.video request is called');
        };


        let ImoUtil = Java.use("com.imo.android.imoim.util.Util");
        ImoUtil.B0.implementation = function(jSONObject){
            console.log('B0 is called');
            let ret = this.B0(jSONObject);
            console.log('B0 ret value is ' + ret);
            return ret;
        };


        let properties_array = {
            "ro.product.model": "ATAT zhopa 255",
            "ro.product.odm.model": "ATAT zhopa 255",
            "ro.product.system.model": "ATAT zhopa 255",
            "ro.product.vendor.model": "ATAT zhopa 255",
            "ro.kernel.qemu": "0",
            "ro.serialno": "ATATA05127377",
            "gsm.operator.numeric": "277030",
            "gsm.sim.operator.numeric": "277030"
        }

        let SystemProperties = Java.use('android.os.SystemProperties');

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(val1, val2) {
            console.log('\x1b[34m', 'SystemProperties vas call', val1, val2, '\x1b[0m')
            if (Object.keys(properties_array).includes(val1)){
                console.log('\x1b[35m', 'SystemProperties return', val1, this.get(properties_array[val1], val2), '\x1b[0m')
                return this.get(properties_array[val1])
            }
            else {
                return this.get(val1, val2)
            }
        }

        Interceptor.attach(Module.findExportByName(null, '__system_property_get'), {
            onEnter: function (args) {
                this._name = args[0].readCString();
                this._value = args[1];
            },
            onLeave: function (retval) {
                console.log('\x1b[36m','NATIVE !', JSON.stringify({
                    result_length: retval,
                    name: this._name,
                    val: this._value.readCString()
                }),'\x1b[0m');
            }
        });

          // Appsflyer
//        let CreateOneLinkHttpTask = Java.use("com.appsflyer.CreateOneLinkHttpTask");
//        CreateOneLinkHttpTask.AFKeystoreWrapper.implementation = function(httpsURLConnection){
//            console.log('AFKeystoreWrapper is called');
//            let ret = this.AFKeystoreWrapper(httpsURLConnection);
//            console.log('AFKeystoreWrapper ret value is ' + ret);
//            return ret;
//        }

//  ------------- BOLT -------------

//        let e0 = Java.use("com.veriff.sdk.internal.e0");
//        e0.a.overload('java.lang.String').implementation = function(str){
//            console.log('a is called');
//            let ret = this.a(str);
//            console.log('a ret value is ' + ret);
//            return ret;
//        };
//
//        //
//        Java.enumerateLoadedClasses({
//            "onMatch": function(c) {
//                if (c.includes("GetAppStateOnStartupRequest")) {
//                    console.log(c);
//                }
//            },
//            onComplete: function() {}
//        });
//
//        Java.choose("ee.mtakso.client.core.data.network.models.user.GetAppStateOnStartupRequest",{
//            onMatch: function (instance){
//                console.log('\x1b[35m', instance, '\x1b[0m')
//            },
//
//            onComplete: function() { console.log();}
//
//        });

    // ---------- end -------------
    });
}, 0);

