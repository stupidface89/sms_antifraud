from api_master.device_build import DeviceBuild
from api_master.task import Task

from prepare_emulator.frida_scripts.common.frida_ssl_unpinning import frida_ssl_unpinning
from prepare_emulator.frida_scripts.common.frida_main import (build_identifies_script, android_identifies_script,
                                                              telephony_identifier_script)


def imo_script(device_build: DeviceBuild, task: Task) -> str:

    script = build_identifies_script(device_build=device_build, task=task)
    script += android_identifies_script()
    script += telephony_identifier_script(task=task)
    #script += frida_ssl_unpinning()

    bypass_finding_root_rules = """
    Java.perform(function() {
        // Метод ищет файлы в системе, которые свойственны наличию рут прав
        let l = Java.use("e7.l");
        l.a.implementation = function(str){
            console.log('[*] Try to find SU files, we catch that and return - False');
            let ret = this.a(str);
            console.log('a ret value is ' + ret);
            return false;
        };
    });
    """

    catch_serialno_params = """
    // Функция генерации рандомного ro.serialno
    function makeid(length) {
        let result           = '';
        let characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        let charactersLength = characters.length;
        let digits = '0123456789';
        for (let i = 0; i < 2; i++ ) {
          result += characters.charAt(Math.floor(Math.random() * 
          charactersLength));
        }
        for (let i=0; i < 3; i++) {
            result += digits.charAt(Math.floor(Math.random() * 11));
        }   
        for (let i = 0; i < 1; i++ ) {
          result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        for (let i=0; i < 6; i++) {
            result += digits.charAt(Math.floor(Math.random() * 11));
        }  
        
        return result;
    }
        
    Java.perform(function() {
        let e = Java.use("v6.a.a.b.y.e");
        e.r.implementation = function(var1, var2){
            console.log('r is called');
            let ret = this.r(var1, var2);
            
            if(var1 == 'ro.serialno') {
                console.log('[!] ro.serialno was called !!!', var1, var2)
                return makeid(8)
            }
            
            console.log('r ret value is ' + ret);
            return ret;
        };
        
        let m0 = Java.use("c.a.a.a.s.m0");
        m0.d.implementation = function(){
            console.log('d is called');
            let ret = this.d();
            console.log('d ret value is ' + ret);
            return ret;
        };
        
    });
    """

    catch_hardware_params = """
        Java.perform(function () {
            
            // Возвращает рандомное значение из массива
            function arrayRandElement(arr) {
                let rand = Math.floor(Math.random() * arr.length);
                return arr[rand];
            }

            // Приложение вызывает метод для получения доп инфы об устройстве(Частота и модель процессора, количество ядер,
            // количество оперативной памяти, и т.д - подменяем возвращаемые значения, для этого формируем профиль устройства)
            let device_hardware = {
                'MEMORY_SIZE': ['2048MB', '3072MB', '4096MB', '6144MB'],
                'CPU_HZ': ['900', '1100', '1250', '850'],
                'CPU_CORES': ['4', '6', '8']
            }

            let device_profile = {
                'MEMORY_SIZE': arrayRandElement(device_hardware['MEMORY_SIZE']),
                'CPU_HZ': arrayRandElement(device_hardware['CPU_HZ']),
                'CPU_CORES':arrayRandElement(device_hardware['CPU_CORES']),
                'CPU_MODEL': '%s'
            }
            let z5 = Java.use("c.a.a.a.s.z5");

            z5.k.implementation = function(val1, val2){
    
                if(val1 == 'MEMORY_SIZE') {
                    console.log('We intercept call with MEMORY_SIZE and return - ', device_profile[val1]);
                    return String.$new(device_profile[val1])
    
                } else if(val1 == 'CPU_HZ'){
                    console.log('We intercept call with CPU_HZ and return - ', device_profile[val1]);
                    return String.$new(device_profile[val1])
    
                } else if(val1 == 'CPU_CORES') {
                    console.log('We intercept call with CPU_CORES and return - ', device_profile[val1]);
                    return String.$new(device_profile[val1])
    
                } else if(val1 == 'CPU_MODEL') {
                    console.log('We intercept call with CPU_CORES and return - ', device_profile[val1]);
                    return String.$new(device_profile[val1])
    
                } else {
                    let ret = this.k(val1, val2);
                    console.log('k ret value is ' + ret);
                    return ret;
                }
            };
            
            let Util = Java.use("com.imo.android.imoim.util.Util");
            Util.i1.implementation = function(){
                console.log('i1 is called !!!!');
                let ret = this.i1();
                console.log('i1 ret value is ' + ret);
                return ret
            };
                        
        });
    
    """ % (device_build.board,)

    script += bypass_finding_root_rules
    script += catch_serialno_params
    #script += catch_hardware_params

    return script
