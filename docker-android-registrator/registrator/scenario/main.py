import subprocess
import time
from typing import NoReturn

from prepare_emulator.exceptions import FridaScenarioDoesntExist
from requests.exceptions import RequestException
from appium import webdriver
from frida import NotSupportedError, InvalidArgumentError

from .exceptions import UnknownServiceException, CouldNotCreateAppiumDriverException, FailedCompleteScenarioException

from scenario.registration.telegram import telegram_registration
from scenario.registration.signal import signal_registration
from scenario.registration.bolt import bolt_registration
from scenario.registration.zenly import zenly_registration
from scenario.registration.imo import imo_registration
from scenario.registration.onexbet import onexbet_registration
from scenario.registration.liveme import liveme_registration

from prepare_emulator.frida_main import FridaInject
from api_antifraud.antifraud import Antifraud
from api_antifraud.exceptions import SmsNotReceivedException
from api_master.task import Task, send_operation_status
from api_master.device_build import DeviceBuild
from api_master.name import get_name
from api_master.city import City

from settings import (logging_info, logging_error, APK_PATHS, adb_executor_path, APK_ACTIVITY, capture_screenshot)


class Scenario(object):
    def __init__(self, device_name: str, task: Task, city: City, device_build: DeviceBuild):
        self.task = task
        self.city = city

        self.token = self.task.token
        self.title_service = self.task.title_service.lower()
        self.short_service = self.task.short_service

        self.emulator_name = device_name
        self.device_build = device_build

        self.antifraud = Antifraud(task=self.task)

        self.scenarios = {
            'telegram': {'reg': 'telegram_registration'},
            'signal': {'reg': 'signal_registration'},
            'bolt': {'reg': 'bolt_registration'},
            'zenly': {'reg': 'zenly_registration'},
            'imo': {'reg': 'imo_registration'},
            'onexbet': {'reg': 'onexbet_registration'},
            'liveme': {'reg': 'liveme_registration'},
         }

        self.desired_caps = {'platformName': 'Android',
                             'platformVersion': '10',
                             'automationName': 'UiAutomator2',
                             'deviceName': self.emulator_name,
                             'newCommandTimeout': 480,
                             'noReset': True,
                             'dontStopAppOnReset': True,
                             'autoLaunch': False,
                             'appWaitDuration': 60000,
                             'deviceReadyTimeout': 30,
                             'androidDeviceReadyTimeout': 30
                             }

        self.phone_number = None
        self.driver = self._create_driver()
        self._prepare_driver(full_reset=False, clear_system_files=False)
        self._install_apk()

    def _prepare_driver(self, full_reset=False, clear_system_files=False) -> NoReturn:
        """
        Метод осуществляет первичную анонимизацию:
            1) Меняет локаль устройства.
            2) Меняет язык устройства.
            3) Геолокацию
        Берем название appPackage и Main Activity из словаря APK_ACTIVITY, в соответсвтии с запрошенным
        сервисом, из settings.py приложения.
        """

        self.desired_caps['locale'] = 'uk_UA'
        self.desired_caps['language'] = 'ua'

        if full_reset:
            self.desired_caps['fullReset'] = True

        if clear_system_files:
            self.desired_caps['clearSystemFiles'] = True

        try:
            package_name = APK_ACTIVITY.get(self.title_service)['appPackage']
            main_activity = APK_ACTIVITY.get(self.title_service)['appActivity']
        except TypeError as e:
            logging_info('Не удалось найти в APK_ACTIVITY сведения о сервис - '
                         f'{self.title_service} (Main Activity и appPackage name)')
            raise CouldNotCreateAppiumDriverException from e
        else:
            self.desired_caps['appPackage'] = package_name
            self.desired_caps['appActivity'] = main_activity

        # Меняем геолокацию
        self.driver.set_location(latitude=self.city.latitude, longitude=self.city.longitude)

    def _create_driver(self) -> webdriver.Remote:
        """
        Создаем драйвер подключения к Appium
        """
        logging_info(f'Подключаемся к Appium {self.emulator_name}')

        driver = webdriver.Remote('http://localhost:4723/wd/hub',
                                  desired_capabilities=self.desired_caps)
        return driver

    def _install_apk(self) -> NoReturn:
        if self.short_service not in APK_PATHS:
            raise UnknownServiceException

        subprocess.run([adb_executor_path(), 'install', APK_PATHS.get(self.short_service)])

    def _service_controller_frida(self) -> NoReturn:
        """
        Проверяет, есть ли сценарий для фриды для полученного сервиса, если есть, то выполняет его
        """
        try:
            getattr(FridaInject, self.title_service)
        except AttributeError as e:
            raise FridaScenarioDoesntExist from e

    def _service_controller_appium(self) -> NoReturn:
        """
        Проверяет, есть ли сценарий для appiuma для полученного сервиса, если есть, то выполняет его
        """
        try:
            getattr(Scenario, self.title_service)
        except AttributeError as e:
            logging_error(f'Сценарий сервиса {self.title_service} для Appium не найден', exception=e)
            raise

    def telegram_registration(self) -> NoReturn:
        telegram_registration(driver=self.driver, antifraud=self.antifraud, name=get_name(), task=self.task)

    def signal_registration(self) -> NoReturn:
        signal_registration(driver=self.driver, antifraud=self.antifraud, name=get_name(), task=self.task)

    def bolt_registration(self) -> NoReturn:
        bolt_registration(driver=self.driver, antifraud=self.antifraud, name=get_name(), task=self.task)

    def zenly_registration(self) -> NoReturn:
        zenly_registration(driver=self.driver, antifraud=self.antifraud, name=get_name(), task=self.task)

    def imo_registration(self) -> NoReturn:
        imo_registration(driver=self.driver, antifraud=self.antifraud, name=get_name(), task=self.task)

    def onexbet_registration(self) -> NoReturn:
        onexbet_registration(driver=self.driver, antifraud=self.antifraud, name=get_name(), task=self.task)

    def liveme_registration(self) -> NoReturn:
        liveme_registration(driver=self.driver, antifraud=self.antifraud, name=get_name(), task=self.task)

    def start_scenario(self) -> dict:
        self._prepare_driver(full_reset=False, clear_system_files=False)

        time.sleep(3)
        try:
            frida_inject = FridaInject(device_build=self.device_build, task=self.task)
        except (NotSupportedError, InvalidArgumentError) as e:
            logging_error('Не удалось запустить Frida на устройстве', exception=e)
            raise

        time.sleep(3)
        try:
            # Вызываем у объекта frida_inject метод, в который соответствует полному названию сервиса (title service)
            service_frida_inject = getattr(frida_inject, self.title_service)
        except AttributeError(f'Не найден сценарий для выполнения {self.title_service} у Frida_inject'):
            raise
        except Exception as e:
            logging_error('Не удалось выполнить сценарий Frida', exception=e)
            raise e

        try:
            service_frida_inject()
        except (NotSupportedError, InvalidArgumentError):
            raise
        except Exception as e:
            logging_error('Не удалось выполнить сценарий Frida', exception=e)
            raise e

        # Ищем имя сценария в словаре соответствия сценарий - сервис
        try:
            scenario_name = self.scenarios.get(self.title_service)['reg']
        except TypeError('Не удалось найти имя сценарий в self.scenarios'):
            raise

        try:
            scenario = getattr(self, scenario_name)
        except AttributeError(f'Сценарий для сервиса {self.title_service} не найден'):
            raise
        except Exception as e:
            raise Exception(e)

        try:
            account_data = scenario()
        except SmsNotReceivedException as e:
            send_operation_status(operation_id=self.task.operation_id, status='no_sms')
            raise FailedCompleteScenarioException from e

        except Exception as e:
            # После вызова исключения, делаем скриншот экрана устройства
            capture_screenshot(self.driver, self.title_service)
            time.sleep(1)

            if self.antifraud.operation_id is not None:
                self.antifraud.send_status(8)

            logging_error('Не удалось выполнить сценарий', exception=e)
            raise FailedCompleteScenarioException from e

        try:
            #self.antifraud.send_account_data(account_data)
            self.antifraud.send_status(6)
            send_operation_status(operation_id=self.task.operation_id, status='completed')
        except RequestException:
            raise

        self.driver.quit()

        time.sleep(2)
        return account_data
