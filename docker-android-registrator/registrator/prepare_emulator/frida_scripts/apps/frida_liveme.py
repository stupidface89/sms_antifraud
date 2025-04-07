from api_master.device_build import DeviceBuild
from api_master.task import Task

from prepare_emulator.frida_scripts.common.frida_main import (build_identifies_script, android_identifies_script,
                                                              telephony_identifier_script)


def liveme_script(device_build: DeviceBuild, task: Task) -> str:

    script = build_identifies_script(device_build=device_build, task=task)
    script += android_identifies_script()
    script += telephony_identifier_script(task=task)

    return script
