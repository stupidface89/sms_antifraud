import subprocess
import os
import time
import signal
import platform
import random

from selenium.webdriver.common.utils import is_connectable

from api_master.task import Task, Proxy
from api_master.device_build import DeviceBuild

from settings import (REDSOCKS_PATH, adb_command, emulator_executor_path, logging_info, logging_error, disable_wifi,
                      adb_executor_path, LOCALE, TIMEZONE)
from .exceptions import DeviceNotFoundException, CouldNotStartEmulator


class Emulator(object):
    def __init__(self):
        self.os = platform.system()
        self.proxy = None
        self.emulator_name = None
        self.pid = None
        self.emulator_port = '5554'

    @staticmethod
    def _start_appium_server(port=4723, show_logs=False):
        command = ['appium', '--address', '127.0.0.1', '--port', str(port)]
        if show_logs is False:
            command.extend(['--log-level', 'error:debug'])
        if not is_connectable(port):
            subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            time.sleep(5)

    @staticmethod
    def _create_config_file(proxy: Proxy):
        """
        Ожидает подготовленный словарь прокси со всеми параметрами, при использовании которых
        создаётся конфиг для редсокса
        """
        config_redsocks = os.path.abspath(os.path.join(REDSOCKS_PATH, 'redsocks.conf'))

        config_text = ('base {\n'
                       'log_info = on;\n'
                       'log_debug = on;\n'
                       'log = "file:/data/bootchart/redsocks.log";\n'
                       'daemon = on;\n'
                       'redirector = iptables;\n'
                       '}\n'
                       '\n'
                       'redsocks {\n'
                       'local_ip = "127.0.0.1"; local_port = "8123";\n'
                       f'ip = "{proxy.address}"; '
                       f'port = "{proxy.port}"; type = socks5;\n'
                       f'login = "{proxy.login}"; '
                       f'password = "{proxy.password}";\n'
                       '}\n')

        with open(config_redsocks, 'w') as file:
            file.write(config_text)
            file.close()

    def _copy_and_run_redsocks_on_device(self):
        """
        Метод перебрасывает на устройство конфиг редсокса и производит его
        запуск, а также добавляет в iptables правила, чтобы перенапривать весь
        трафик на редсокс.
        """
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setenforce', '0'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'mount', '-orw,remount', '/'])
        #adb_command(['-s', self.device, 'shell', 'su', '0', 'mount', '-orw,remount', '/data'])

        # Копируем редксокс и конфиг на устройство
        time.sleep(1)
        adb_command(['-s', self.emulator_name, 'push', os.path.join(REDSOCKS_PATH, 'redsocks'), '/data/bootchart/'])
        
        time.sleep(1)
        adb_command(['-s', self.emulator_name, 'push', os.path.join(REDSOCKS_PATH, 'redsocks.conf'), '/data/bootchart/'])

        # Навешиваем права на исполняемый файл редсокс 755
        time.sleep(1)
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'chmod 755', '/data/bootchart/redsocks'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'chmod 755', '/data/bootchart/redsocks.conf'])

        # Убиваем процесс redosocks на устройстве, если был
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'killall', 'redsocks'])

        # Запускаем редсокс на устройстве
        time.sleep(3)
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', './data/bootchart/redsocks', '-c', '/data/bootchart/redsocks.conf'])

    def _configure_iptables(self, proxy: Proxy):
        """
        Метод выполняет манипуляции с iptables на устройстве, для
        перенаправление трафика через redsocks
        """
        # Преобразовываем адрес прокси в адрес подсети и маски в вид - 72.15.255.0/16
        subnet = proxy.address.split('.')[0:-1]
        subnet.append('0')
        subnet = (".".join(subnet))+'/16'

        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-F', 'OUTPUT'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-F', 'OUTPUT'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-X', 'PROXY'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-N', 'PROXY'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-F', 'PROXY'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-d', '0.0.0.0/8', '-j', 'RETURN'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-d', '10.0.0.0/8', '-j', 'RETURN'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-d', '127.0.0.0/8', '-j', 'RETURN'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-d', '169.254.0.0/16', '-j', 'RETURN'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-d', '172.16.0.0/12', '-j', 'RETURN'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-d', '192.168.0.0/16', '-j', 'RETURN'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-d', '240.0.0.0/4', '-j', 'RETURN'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-d', subnet, '-j', 'RETURN'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-p', 'tcp', '-j', 'REDIRECT', '--to-ports', '8123'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'OUTPUT', '-p', 'tcp', '-m', 'owner', '!', '--uid-owner', 'shell', '-j', 'PROXY'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'PROXY', '-p', 'udp', '--dport', '53', '-j', 'DNAT', '--to', '8.8.8.8'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-t', 'nat', '-A', 'OUTPUT', '-p', 'udp', '-j', 'PROXY'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'iptables', '-A', 'OUTPUT', '-p', 'udp', '-j', 'DROP'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'bst.dns_server', '8.8.8.8'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'bst.dns_server2', '8.8.4.4'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'net.dns1', '8.8.8.8'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'net.dns2', '8.8.4.4'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'ndc', 'resolver', 'setnetdns', 'eth0', '8.8.8.8', '8.8.4.4'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'net.eth0.dns1', '8.8.8.8'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'net.eth0.dns2', '8.8.4.4'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'dhcp.eth0.dns1', '8.8.8.8'])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'dhcp.eth0.dns2', '8.8.4.4'])

    def _configure_device_properties(self, task: Task, device_build: DeviceBuild):
        processors = ['Cortex-A53', 'Cortex-A57', 'Cortex-A72', 'Cortex-A73', 'Cortex-A55', 'Cortex-A75', 'Cortex-A76',
                      'Cortex-A77', 'Cortex-A78', 'Cortex-X1']
        choice_processor = random.choice(processors)

        # Telephony Manager section
        logging_info(message=f'\n [*] gsm.operator.alpha - {task.operator} \n [*] gsm.sim.operator.alpha - {task.operator}', set_color='magenta')
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'gsm.operator.alpha', task.operator])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'gsm.sim.operator.alpha', task.operator])

        logging_info(message=f'\n [*] gsm.operator.iso-country - {task.country.lower()} \n [*] gsm.sim.operator.iso-country - {task.country.lower()}', set_color='magenta')
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'gsm.operator.iso-country', task.country.lower()])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'gsm.sim.operator.iso-country', task.country.lower()])

        mccmnc = task.mcc + task.mnc
        logging_info(message=f'\n [*] gsm.operator.numeric - {task.mcc + task.mnc} \n [*] gsm.sim.operator.numeric - {mccmnc}', set_color='magenta')
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'gsm.operator.numeric', mccmnc])
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'gsm.sim.operator.numeric', mccmnc])

        # Hardware section
        logging_info(message=f'\n [*] net.bt.name - "{device_build.manufacturer}"', set_color='magenta')
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'net.bt.name', device_build.manufacturer])

        logging_info(message=f'\n [*] qemu.sf.fake_camera - ""', set_color='magenta')
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'qemu.sf.fake_camera', '\"\"'])

        logging_info(message=f'\n [*] dalvik.vm.isa.arm64.variant - {choice_processor}', set_color='magenta')
        adb_command(['-s', self.emulator_name, 'shell', 'su', '0', 'setprop', 'dalvik.vm.isa.arm64.variant', choice_processor])

        # Battery section Рандомное значение заряда батареи, жизнеспособности? и температуры(253/10 = 25,3*)
        adb_command(['-s', self.emulator_name, 'shell', 'dumpsys', 'battery', 'set', 'level', f'{random.randint(23, 96)}'])
        adb_command(['-s', self.emulator_name, 'shell', 'dumpsys', 'battery', 'set', 'counter', f'{random.randint(10500, 13500)}'])
        adb_command(['-s', self.emulator_name, 'shell', 'dumpsys', 'battery', 'set', 'temp', f'{random.randint(200, 300)}'])

    @staticmethod
    def _get_devices_list():
        """Получаем список созданных устройств для эмулятора"""
        emulator_path = emulator_executor_path()
        devices_list = subprocess.run([emulator_path, "-list-avds"],
                                      stdout=subprocess.PIPE,
                                      encoding='utf=8').stdout.splitlines()

        if len(devices_list) < 1:
            raise DeviceNotFoundException
        return devices_list

    def run_emulator(self, task: Task, wipe_data: bool = True, memory: int = 2048,):
        """
        Запускаем эмулятор 
        """

        if not TIMEZONE.get(task.country):
            raise CouldNotStartEmulator(f'Ну удалось найти временную зону {task.country} в словаре '
                                        'TIMEZONE из settings.py')

        tz = TIMEZONE.get(task.country)

        if not LOCALE.get(task.country):
            raise CouldNotStartEmulator(f'Ну удалось найти языковую локализацию {task.country} в словаре '
                                        'LOCALE из settings.py')

        locale = LOCALE.get(task.country)

        command = [emulator_executor_path(), '-avd', self._get_devices_list()[0], '-port', self.emulator_port]

        if task.title_service.lower() not in ['telegram']:
            command += ['-change-locale', locale]

        command += ['-no-snapshot', '-nocache', '-no-snapshot-load',
                    '-timezone', tz,
                    '-dns-server', '8.8.8.8',
                    '-no-boot-anim',
                    '-accel', 'on',
                    '-gpu', 'off',
                    '-no-audio',
                    #'-no-window',
                    '-memory', str(memory)]

        # Выводим в логи режим запуска эмулятора
        if 'no-window' in command:
            logging_info('Запускаем эмулятор в режиме NO-WINDOW', set_color='magenta')
        logging_info('Запускаем эмулятор в режиме WINDOW', set_color='magenta')

        if wipe_data is True:
            command.append('-wipe-data')
        
        try:
            adb_command(['start-server'])
            emulator = subprocess.Popen(command)

        except CouldNotStartEmulator as e:
            logging_error(f'Не удалось запустить устройство emulator-{self.emulator_port}', exception=e)
            raise

        else:
            logging_info(f'Устройство emulator-{self.emulator_port} запускается \n \n'
                         '# # # # # # # # # # # # # # # # # # # # # # # # # # # #\n')
            time.sleep(20)

            self.emulator_name = f'emulator-{self.emulator_port}'
            self.pid = emulator.pid

            logging_info(f'\n # # # # # # # # # # # # # # # # # # # # # # # # # # # # \n \n'
                         f'Устройство запущено emulator-{self.emulator_port} pid={self.pid}')

    def kill_process_emulator(self):
        logging_info(f'Убиваем процесс эмулятора {self.pid}')
        if self.os == 'Windows':
            try:
                subprocess.run([f'taskkill, /PID, {self.pid}'])
            except FileNotFoundError as e:
                logging_error('Не удалось завершить процесс, '
                              f'процесса {self.pid} не существует', exception=e)
        else:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError as e:
                logging_error('Не удалось завершить процесс, '
                              f'процесса {self.pid} не существует', exception=e)

        time.sleep(2)

    def shutdown_device(self):
        logging_info(f'Выключаем устройство ')
        if self.emulator_name is not None:
            subprocess.run([adb_executor_path(), '-s', self.emulator_name, 'shell', 'reboot', '-p'], )
            time.sleep(15)

    def prepare(self, proxy: Proxy, task: Task, device_build: DeviceBuild):
        logging_info('Подготавливаем к запуску эмулятор')

        time.sleep(2)
        logging_info(f'Создаем конфиг для redsocks')
        self._create_config_file(proxy)

        time.sleep(2)
        logging_info(f'Запускаем redsocks на устройстве с использованием конфига')
        self._copy_and_run_redsocks_on_device()

        disable_wifi()

        time.sleep(2)
        logging_info(f'Производим настройку iptables в соответствии с выбранным proxy')
        self._configure_iptables(proxy)

        time.sleep(1)
        logging_info(f'Производим настройку параметров устройства')
        #self._configure_device_properties(device_build=device_build, task=task)

        logging_info(f'Подгодовка устройства {self.emulator_name} к работе успешно выполнена')


