from api_master.device_build import DeviceBuild
from api_master.task import Task

from prepare_emulator.frida_scripts.common.frida_main import build_identifies_script, android_identifies_script, telephony_identifier_script


def bolt_script(device_build: DeviceBuild, task: Task) -> str:

    script = build_identifies_script(device_build=device_build, task=task)
    script += android_identifies_script()
    script += telephony_identifier_script(task=task)

    device_name = device_build.manufacturer + device_build.model
    bolt_change_query_params = """
        Java.perform(function() {
            let String = Java.use('java.lang.String')
            let EnvironmentInfo = Java.use('ee.mtakso.client.core.data.constants.EnvironmentInfo')
            EnvironmentInfo.getDeviceVersionName.implementation = function () {
                console.log('[*] Intercept original device info - ', this.getDeviceVersionName())
                return String.$new('%s');
            }
        });
    """ % (device_name,)

    bolt_show_query = """
        // Отображает запрос к API
        Java.perform(function() {
            let Request = Java.use('ee.mtakso.client.core.data.network.interceptors.TaxifyRequestInterceptor')
            Request.addConstantQueryParams.overload('okhttp3.t$a').implementation = function(val1) {
                console.log(this.addConstantQueryParams(val1))
                return this.addConstantQueryParams(val1);
            }
        });
    """

    script += bolt_change_query_params
    #script += bolt_show_query

    return script
