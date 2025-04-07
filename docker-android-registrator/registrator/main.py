import logging
import sys
import time
import sentry_sdk

from datetime import datetime
from typing import NoReturn

from settings import logging_error, logging_info, disable_wifi
from prepare_emulator.main import Emulator
from prepare_emulator.exceptions import CouldNotStartEmulator, CouldNotPrepareDevice

from scenario.main import Scenario
from scenario.exceptions import CouldNotCreateAppiumDriverException, FailedCompleteScenarioException
from api_master.city import get_city, City
from api_master.task import get_task, send_operation_status, Task, Proxy, get_proxy
from api_master.device_build import try_get_build, DeviceBuild
from api_master.exceptions import CouldNotGetDeviceBuild, CouldNotGetProxy, FailedSendStatusOperationException


class AndroidRegistrator(object):
    def __init__(self, task: Task, city: City, proxy: Proxy, device_build: DeviceBuild):

        self.emulator = None
        self.emulator_port = None
        self.emulator_pid = None
        self.task = task
        self.proxy = proxy
        self.city = city
        self.device_build = device_build

    def prepare_device(self):
        try:
            self.emulator = Emulator()
            self.emulator.run_emulator(task=self.task)

        except Exception as e:
            logging_error(f'Не удалось запустить эмулятор \n {str(e)} {sys.exc_info()}', exception=e)
            raise CouldNotStartEmulator from e

        try:
            self.emulator.prepare(proxy=self.proxy,
                                  task=self.task,
                                  device_build=self.device_build)

        except Exception as e:
            logging_error(f'Не удалось подготовить к работе устройство  \n {str(e)} {sys.exc_info()}', exception=e)
            self.emulator.shutdown_device()
            self.emulator.kill_process_emulator()
            raise CouldNotPrepareDevice from e

    def start_scenario(self) -> NoReturn:
        try:
            scenario = Scenario(device_name=self.emulator.emulator_name,
                                device_build=self.device_build,
                                task=self.task,
                                city=self.city)

        except Exception as e:
            logging_error(f'Не удалось получить контроль над устройством  \n {str(e)} {sys.exc_info()}', exception=e)
            self.emulator.shutdown_device()
            self.emulator.kill_process_emulator()
            raise CouldNotCreateAppiumDriverException from e

        try:
            account_data = scenario.start_scenario()
        except Exception as e:
            raise FailedCompleteScenarioException from e
        else:
            logging_info(f'Успешная регистрация \n {account_data}')

        finally:
            self.emulator.shutdown_device()
            self.emulator.kill_process_emulator()


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    logging.basicConfig(format="%(levelname)s - %(message)s")

    # Инициализируем сентри
    sentry_sdk.init(dsn="https://0cd0c27e96044ceaac0cc44baf17d6e2@o506018.ingest.sentry.io/6742715",
                    traces_sample_rate=1.0)

    # Вход в приложение
    def task_controller() -> NoReturn:
        while True:
            timestamp = datetime.now()

            # Запрашиваем у API задачу
            try:
                task = get_task()
            except Exception as e:
                logging_info(f'Не удалось взять в работу задачу  \n {str(e)}')
                continue

            # Берем из полученной задачи прокси
            try:
                proxy = get_proxy(task.proxy)
            except Exception as e:
                logging_info(f'Не удалось получить прокси \n {str(e)}', set_color='red')
                time.sleep(60)
                continue

            # Запрашиваем у API город
            try:
                city = get_city()
            except Exception as e:
                logging_info(f'Не удалось получить от API город  \n {str(e)}')
                continue

            # Запрашиваем у API сборку устройства
            try:
                device_build = try_get_build()
            except Exception as e:
                logging_info(f'Не удалось получить сборку устройства \n {str(e)}', set_color='red')
                continue

            try:
                android_registrator = AndroidRegistrator(task=task, proxy=proxy, city=city, device_build=device_build)
                android_registrator.prepare_device()
                android_registrator.start_scenario()

            except Exception as e:
                logging_error(str(e), exception=e)
                # Отправляем на API статус об неудачном выполнении операции
                send_operation_status(operation_id=task.operation_id, status='failed')
                continue

            timestamp = datetime.now() - timestamp
            logging_info(f'Время выполнения {timestamp}')


    task_controller()
