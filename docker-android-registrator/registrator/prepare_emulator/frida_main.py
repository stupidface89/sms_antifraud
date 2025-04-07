import frida
import os
import subprocess

from prepare_emulator.frida_scripts.apps.frida_telegram import telegram_script
from prepare_emulator.frida_scripts.apps.frida_signal import signal_script
from prepare_emulator.frida_scripts.apps.frida_bolt import bolt_script
from prepare_emulator.frida_scripts.apps.frida_zenly import zenly_script
from prepare_emulator.frida_scripts.apps.frida_imo import imo_script
from prepare_emulator.frida_scripts.apps.frida_onexbet import onexbet_script
from prepare_emulator.frida_scripts.apps.frida_liveme import liveme_script

from api_master.device_build import DeviceBuild
from api_master.task import Task
from settings import (FRIDA_SERVER_PATH, adb_executor_path, logging_info, adb_command)


class FridaInject(object):
    def __init__(self, device_build: DeviceBuild, task: Task):
        self.device_build = device_build
        self.task = task
        self._push_frida_server(path=FRIDA_SERVER_PATH)

    @staticmethod
    def _push_frida_server(path):
        """
        Выполнять только после получения рута
        """
        logging_info('Закачиваем сервер Frida на устройство')

        file_name = os.path.basename(path)
        adb_command(['shell', 'su', '0', f'killall {file_name}'])
        adb_command(['push', path, '/data/local/tmp'])
        adb_command(['shell', 'su', '0', 'chmod', '755', f'/data/local/tmp/{file_name}'])

        logging_info('Запускаем сервер Frida')
        subprocess.Popen([adb_executor_path(), 'shell', 'su', '0', f'./data/local/tmp/{file_name}'])
        logging_info('Сервер Frida запущен')

    @staticmethod
    def on_message(message, data):
        if 'payload' in message:
            payload = message['payload']
            if 'level' in payload:
                print("[{0}] {1}".format(payload['level'], payload['message']))
            else:
                print("[*] {0}".format(message['payload']))
        else:
            print(message)

    def telegram(self):
        """Telegram app"""

        device = frida.get_usb_device()
        pid = device.spawn("org.telegram.messenger")
        session = device.attach(pid)

        script = session.create_script(telegram_script(self.device_build,
                                                       task=self.task))
        script.on('message', self.on_message)
        script.load()
        device.resume(pid)

    def signal(self):
        """Signal app"""
        logging_info('Выполняем скрипт Frida для Signal')

        device = frida.get_usb_device()
        pid = device.spawn("org.thoughtcrime.securesms")
        session = device.attach(pid)

        script = session.create_script(signal_script(device_build=self.device_build,
                                                     task=self.task))
        script.on('message', self.on_message)
        script.load()
        device.resume(pid)

    def uber(self):
        """Uber app"""
        logging_info('Выполняем скрипт Frida для Uber')

        device = frida.get_usb_device()
        pid = device.spawn("")
        session = device.attach(pid)

        script = session.create_script(ub_script(device_build=self.device_build,
                                                 task=self.task))
        script.on('message', self.on_message)
        script.load()
        device.resume(pid)

    def bolt(self):
        """Bolt app"""
        logging_info('Выполняем скрипт Frida для Bolt')

        device = frida.get_usb_device()
        pid = device.spawn("ee.mtakso.client")
        session = device.attach(pid)

        script = session.create_script(bolt_script(device_build=self.device_build,
                                                   task=self.task))
        script.on('message', self.on_message)
        script.load()
        device.resume(pid)

    def zenly(self):
        """Zenly app"""
        logging_info('Выполняем скрипт Frida для Zenly')

        device = frida.get_usb_device()
        pid = device.spawn("app.zenly.locator")
        session = device.attach(pid)

        script = session.create_script(zenly_script(self.device_build,
                                                    task=self.task))
        script.on('message', self.on_message)
        script.load()
        device.resume(pid)

    def imo(self):
        """IMO app"""
        logging_info('Выполняем скрипт Frida для IMO')

        device = frida.get_usb_device()
        pid = device.spawn("com.imo.android.imoim")
        session = device.attach(pid)

        script = session.create_script(imo_script(self.device_build, task=self.task))
        script.on('message', self.on_message)
        script.load()
        device.resume(pid)

    def onexbet(self):
        """1xbet app"""
        logging_info('Выполняем скрипт Frida для OnexBet')

        device = frida.get_usb_device()
        pid = device.spawn("org.xbet.client1")
        session = device.attach(pid)

        script = session.create_script(onexbet_script(self.device_build, task=self.task))
        script.on('message', self.on_message)
        script.load()
        device.resume(pid)

    def liveme(self):
        """LiveMe app"""
        logging_info('Выполняем скрипт Frida для LiveMe')

        device = frida.get_usb_device()
        pid = device.spawn("com.plusme.live")
        session = device.attach(pid)

        script = session.create_script(liveme_script(self.device_build, task=self.task))
        script.on('message', self.on_message)
        script.load()
        device.resume(pid)
