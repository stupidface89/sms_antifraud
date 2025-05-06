from settings import logging_info

from api_master.task import Task
from api_master.device_build import DeviceBuild
from prepare_emulator.frida_scripts.common.frida_main import build_identifies_script, android_identifies_script, telephony_identifier_script


def telegram_script(device_build: DeviceBuild, task: Task) -> str:
    logging_info('Выполняем скрипт Frida для Telegram')

    script = build_identifies_script(device_build=device_build, task=task)
    script += android_identifies_script()
    script += telephony_identifier_script(task=task)

    telegram_bypass_emudetect = """
    Java.perform(()=>{
        let EmuDetector = Java.use('org.telegram.messenger.EmuDetector');

        EmuDetector.detect.implementation = function () {
            console.log('[!] Emulator Detector was call.', 'We catch that and return False instead', this.detect());
            return false;
        }
    });
    """
    script += telegram_bypass_emudetect
    return script
