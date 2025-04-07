from api_master.device_build import DeviceBuild
from api_master.task import Task

from prepare_emulator.frida_scripts.common.frida_main import build_identifies_script, android_identifies_script, telephony_identifier_script


def signal_script(device_build: DeviceBuild, task: Task) -> str:

    script = build_identifies_script(device_build=device_build, task=task)
    script += android_identifies_script()
    script += telephony_identifier_script(task=task)

    signal_get_registration_data = """
        setTimeout(function() {
            Java.perform(function() {
                let ServiceResponse = Java.use('org.whispersystems.signalservice.internal.ServiceResponseProcessor')
                let Response = Java.use("org.whispersystems.signalservice.internal.ServiceResponse");
                let PushServiceSocket = Java.use('org.whispersystems.signalservice.internal.push.PushServiceSocket')
                let RequestVerification = Java.use('org.whispersystems.signalservice.internal.push.RequestVerificationCodeResponse');
                
                
                Response.getStatus.implementation = function() {
                    let status = this.getStatus();
                    console.log('\x1b[34m[*] Response status -', status, '\x1b[0m')
                    return status
                }
                
                ServiceResponse.captchaRequired.implementation = function() {
                    console.log('\x1b[31m[!] Captcha Required is -', this.captchaRequired(), '\x1b[0m')
                    return false
                }
    
                RequestVerification.getFcmToken.implementation = function() {
                    console.log('\x1b[34m[*] Retrieve FcmToken: ', this.getFcmToken(), '\x1b[0m')
                    return this.getFcmToken();
                }
            
                PushServiceSocket.requestPushChallenge.overload('java.lang.String', 'java.lang.String').implementation = function(val1, val2) {
                    console.log('\x1b[34m[*] Request Push Challenge ', val1, val2, '\x1b[0m');
                    return this.requestPushChallenge(val1, val2);
                }
                
                
                let VerifyAccountRepository = Java.use("org.thoughtcrime.securesms.registration.VerifyAccountRepository");
                VerifyAccountRepository.requestVerificationCode.implementation = function(e164, password, mode, str){
                    console.log('requestVerificationCode is called', e164, password, mode, str);
                    let ret = this.requestVerificationCode(e164, password, mode, str);
                    console.log('requestVerificationCode return value is ' + ret);
                    return ret;
                };
                
                // Есть подозрение что за отведенные приложением 5 секунд, из за прокси, не успевает проскочить запрос с токеном на сервер
                VerifyAccountRepository.PUSH_REQUEST_TIMEOUT.value = 20000
                
            });
        }, 0);
    """

    script += signal_get_registration_data

    return script
