from api_master.device_build import DeviceBuild
from api_master.task import Task

from prepare_emulator.frida_scripts.common.frida_main import build_identifies_script, android_identifies_script, telephony_identifier_script


def zenly_script(device_build: DeviceBuild, task: Task) -> str:

    script = build_identifies_script(device_build=device_build, task=task)
    script += android_identifies_script()
    script += telephony_identifier_script(task=task)

    zenly_block_analysis_services = """
    setTimeout(function() {
        Java.perform(function() {
            // f*ing Sentry block requests
            let HttpURLConnection = Java.use('java.net.HttpURLConnection')
            let SentryHttpConnection = Java.use("io.sentry.transport.HttpConnection");
            let URL = Java.use(('java.net.URL'));
            
            SentryHttpConnection.createConnection.implementation = function(){
                let some_url = URL.$new('some-origin')
                let request = HttpURLConnection.$new(some_url)
                 
                console.log('createConnection is called');
                let ret = this.createConnection();
                console.log('createConnection ret value is ' + ret);
                return request
            };
        
            
            let c = Java.use("com.amplitude.api.c");
            c.$init.overload('java.lang.String').implementation = function(str){
                console.log('$init is called');
                console.log('$init ret value is ', str);
            };
    
            let e = Java.use("com.amplitude.api.e");
            e.c.implementation = function(aVar){
                console.log('c get value is ', aVar.value);
            };
    
            // Zenly emudetect by Build's params should return True if we want to will be hide
            let a = Java.use("ud0.a");
            a.f.implementation = function(){
                console.log('f is called');
                console.log('f ret value is ' + ret);
                return Java.use(android.lang.Boolean).$new('true')
            };
    
            // Блокируем запросы Appsflyer
            let AFDeepLinkManager = Java.use("com.appsflyer.AFDeepLinkManager");
            AFDeepLinkManager.ι.overload('android.content.Context', 'java.util.Map', 'android.net.Uri').implementation = function(context, map, uri){
                console.log('ι is called');
            };
    
            let OneLinkHttpTask = Java.use("com.appsflyer.OneLinkHttpTask");
            OneLinkHttpTask.doRequest.implementation = function(){
                console.log('doRequest is called');
                console.log('doRequest ret value is ' + ret);
            };
        });
    }, 0)
    """

    script += zenly_block_analysis_services
    return script
