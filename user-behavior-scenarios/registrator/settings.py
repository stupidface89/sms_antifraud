import os
import subprocess
import platform
import logging
import time
import pytz

from datetime import datetime

os.environ['MASTER_API_URL'] = 'http://192.168.0.15:8000'

MASTER_API_KEY = os.getenv('MASTER_API_KEY')
MASTER_API_URL = os.getenv('MASTER_API_URL')

URL_GET_TASK = MASTER_API_URL + '/api/tasks/get-task/'
URL_GET_DEVICE = MASTER_API_URL + '/api/device/get-device/'
URL_GET_RANDOM_NAME = MASTER_API_URL + '/api/random-name/'
URL_GET_RANDOM_CITY = MASTER_API_URL + '/api/random-city/'
URL_SEND_STATUS_OPERATION = MASTER_API_URL + '/api/operation/send-status/'


APK_ACTIVITY = {'telegram': {'appPackage': 'org.telegram.messenger',
                             'appActivity': 'org.telegram.ui.LaunchActivity'},
                'signal': {'appPackage': 'org.thoughtcrime.securesms',
                           'appActivity': 'org.thoughtcrime.securesms.MainActivity'},
                'bolt': {'appPackage': 'ee.mtakso.client',
                         'appActivity': 'ee.mtakso.client.newbase.RideHailingMapActivity'},
                'uber': {'appPackage': 'com.ubercab',
                         'appActivity': 'com.ubercab.presidio.app.core.root.RootActivity'},
                'imo': {'appPackage': 'com.imo.android.imoim',
                        'appActivity': 'com.imo.android.imoim.activities.ManageSpaceActivity'},
                'zenly': {'appPackage': 'app.zenly.locator',
                          'appActivity': 'app.zenly.locator.MainActivity'},
                'onexbet': {'appPackage': 'org.xbet.client1',
                            'appActivity': 'org.xbet.starter.ui.starter.StarterActivity'},
                'liveme': {'appPackage': 'com.plusme.live',
                           'appActivity': 'org.xbet.starter.ui.starter.StarterActivity'}
                }


TIMEZONE = {'ua': 'Europe/Kiev'}

LOCALE = {'ua': 'uk-UA'}


def logging_debug(message):
    current_time = datetime.now(tz=pytz.timezone('Asia/Krasnoyarsk')).strftime("%d/%m/%Y %H:%M:%S")
    logging.debug(f'{current_time} : {message}')


def logging_info(message, set_color: str = None):

    colors = {'default': '\x1b[0m',
              'magenta': '\x1b[35m',
              'cyan': '\x1b[36m',
              'green': '\x1b[32m',
              'red': '\x1b[31m',
              'yellow': '\x1b[33m',
              'blue': '\x1b[34m'}

    current_time = datetime.now(tz=pytz.timezone('Asia/Krasnoyarsk')).astimezone().strftime("%d/%m/%Y %H:%M:%S")

    if set_color is not None and set_color in colors.keys():
        color_message = colors[set_color]
        default_color = colors.get('default')

        logging.info(f'{current_time} : {color_message}{message} {default_color}')
    else:
        logging.info(f'{current_time} : {message}')


def logging_error(message, exception: object):
    current_time = datetime.now(tz=pytz.timezone('Asia/Krasnoyarsk')).strftime("%d/%m/%Y %H:%M:%S")
    logging.error('\x1b[31m'+f'{current_time} : {message} \n {get_exception_class_name(exception)}'+'\x1b[0m')


def android_home_path():
    if os.getenv('ANDROID_HOME'):
        return os.getenv('ANDROID_HOME')

    logging_info('Переменной окружения ANDROID_HOME не существует, пытаемся определить автоматически')
    current_platform = platform.machine()

    if current_platform == 'arm64':
        os.environ['ANDROID_HOME'] = os.path.abspath(os.path.expanduser('~/Library/Android/sdk'))

    elif current_platform in ['x86', 'x86_64', 'AMD64']:
        path_to_app_local_data = os.getenv('LOCALAPPDATA')
        os.environ['ANDROID_HOME'] = os.path.abspath(os.path.join(path_to_app_local_data, 'Android', 'SDK'))
    
    return os.getenv("ANDROID_HOME")


def by_os_application_path(file_name):
    current_platform = platform.machine()
    if current_platform == 'arm64':
        path = os.path.join('app_binaries', 'arm64', file_name)
        return os.path.abspath(f'./{path}')

    elif current_platform in ['x86', 'x86_64', 'AMD64']:
        path = os.path.join('app_binaries', 'x86', file_name)
        return os.path.abspath(f'./{path}')


def by_os_redsocks_path():
    current_platform = platform.machine()
    if current_platform == 'arm64':
        path = os.path.join('redsocks', 'arm64')
        return os.path.abspath(f'./{path}')

    elif current_platform in ['x86', 'x86_64', 'AMD64']:
        path = os.path.join('redsocks', 'x86')
        return os.path.abspath(f'./{path}')


def by_os_frida_server_path():
    current_platform = platform.machine()
    if current_platform == 'arm64':
        path = os.path.join('app_binaries/frida_server', 'frida-server-15.1.22-arm64')
        return os.path.abspath(f"./{path}")

    elif current_platform == 'x86':
        path = os.path.join('app_binaries/frida_server', 'frida-server-15.1.22-x86')
        return os.path.abspath(f"./{path}")

    elif current_platform == 'x86_64' or current_platform == 'AMD64':
        path = os.path.join('app_binaries/frida_server', 'frida-server-15.1.22-x86_64')
        return os.path.abspath(f"./{path}")


ANDROID_HOME = android_home_path()

MAGISK_PATH = by_os_application_path('Magisk_24.3.apk')
SIGNAL_PATH = by_os_application_path('Signal_5.43.7.apk')
TELEGRAM_PATH = by_os_application_path('Telegram_8.5.4.apk')
BOLT_PATH = by_os_application_path('Bolt_CA.44.0.apk')
ZENLY_PATH = by_os_application_path('Zenly_5.5.3_50050003.apk')
IMO_PATH = by_os_application_path('imo_2022.07.1111.apk')
ONEXBET_PATH = by_os_application_path('1xbet-100(4820).apk')
LIVEME_PATH = by_os_application_path('LiveMe_v1.10.02.apk')

REDSOCKS_PATH = by_os_redsocks_path()
FRIDA_SERVER_PATH = by_os_frida_server_path()


APK_PATHS = {
    'magisk': MAGISK_PATH,
    'tg': TELEGRAM_PATH,
    'sl': SIGNAL_PATH,
    'bl': BOLT_PATH,
    'zn': ZENLY_PATH,
    'imo': IMO_PATH,
    '1x': ONEXBET_PATH,
    'lm': LIVEME_PATH,
}


def adb_executor_path() -> str:
    return os.path.abspath(os.path.join(ANDROID_HOME, 'platform-tools', 'adb'))


def emulator_executor_path() -> str:
    return os.path.abspath(os.path.join(ANDROID_HOME, 'emulator', 'emulator'))


def capture_screenshot(driver, service) -> bool:
    current_time = datetime.now(tz=pytz.timezone('Asia/Krasnoyarsk')).strftime("%H-%M-%S %d-%m-%Y")
    image = driver.get_screenshot_as_file(f'./screenshots/{service} {current_time}.png')
    return image


def adb_command(command, timeout: int = 60):
    """
    В качестве параметра command нужно указывать все команды с ключами
    перечесленные в списке.
    Установлен таймаут на выполнение команды в 60 секунд.
    """
    total_command = [adb_executor_path()]
    for item in command:
        total_command.append(item)

    try:
        subprocess.run(total_command, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        logging_error(f'Превышен таймаут на выполнение команды вызванной subprocess. \n Пытались '
                      f'выполнить - {e.cmd}', exception=e)
        raise
    time.sleep(0.3)


def disable_wifi(delay_before: int = 2):
    time.sleep(delay_before)
    logging_info(message='[*] Выключаем на устройстве Wi-Fi', set_color='magenta')
    adb_command(['shell', 'su', '0', 'svc', 'wifi', 'disable'])


def enable_wifi():
    logging_info(message='[*] Включаем на устройстве Wi-Fi', set_color='magenta')
    adb_command(['shell', 'su', '0', 'svc', 'wifi', 'enable'])


def disable_data():
    logging_info(message='[*] Выключаем на устройстве Data internet', set_color='magenta')
    adb_command(['shell', 'su', '0', 'svc', 'data', 'disable'])
    time.sleep(2)


def enable_data():
    logging_info(message='[*] Включаем на устройстве Data internet', set_color='magenta')
    adb_command(['shell', 'su', '0', 'svc', 'data', 'enable'])
    time.sleep(5)


def get_exception_class_name(obj):
    """
    Если у объекта класса имеется аттрибут модуль, то возвращаем название
    класса исключения с модулем
    """
    module = obj.__class__.__module__
    if module is None or module == str.__class__.__module__:
        return obj.__class__.__name__
    return module + '.' + obj.__class__.__name__
