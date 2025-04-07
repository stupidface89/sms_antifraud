import time
import uuid
import requests
import json
import random
import socket

from requests.exceptions import RequestException, ConnectTimeout, ConnectionError, SSLError, ReadTimeout
from dataclasses import dataclass, field, asdict

from settings import URL_GET_TASK, URL_SEND_STATUS_OPERATION, logging_error, logging_info, MASTER_API_URL
from .exceptions import CouldNotGetTask, AllProxiesDead, IsEmptyTaskProxy


@dataclass
class Task:
    """
    Для запросов у API Антифрод используется short_service, для всех других вызовов методов через getattr используем
    title_service
    """
    token: str
    operation_id: uuid.UUID
    title_service: str
    short_service: str
    country: str
    operator: str
    mcc: str
    mnc: str
    country_code: str
    proxy: list
    task_id: uuid.UUID
    operation_type: str = field(default='reg')


@dataclass
class Proxy:
    login: str
    password: str
    address: str
    port: str
    type: str = field(default='SOCKS5')


def try_get_task(timeout: float = 2.0) -> json:
    while True:
        try:
            task = requests.post(URL_GET_TASK, json={'worker': socket.gethostname()}, timeout=timeout)
        except RequestException:
            logging_info(f'API не отвечает - {MASTER_API_URL}')
            time.sleep(5)
            continue

        if task.status_code != 200:
            time.sleep(5)
            continue

        try:
            task = task.json()
        except AttributeError as e:
            logging_error('Не удалось преобразовать ответ с заданием в JSON', exception=e)
            raise CouldNotGetTask from e

        if not task:
            logging_info('Задачи на текущий час выполнены, пробуем снова', set_color='cyan')
            time.sleep(30)
            continue
        return task
    raise CouldNotGetTask


def send_operation_status(operation_id: uuid.UUID, status: str, amount: int = 5) -> requests.status_codes:
    """
    Статусы: ['new', 'started, 'no_sms', 'failed', 'completed']

    """

    logging_info(f'Отправляем на MASTER API статус {status}', set_color='blue')
    while amount > 0:
        try:
            response = requests.post(URL_SEND_STATUS_OPERATION,
                                     headers={"Content-Type": "application/json"},
                                     json={"status": status, "operation": operation_id})

        except Exception as e:
            logging_info(e)
            time.sleep(3)
            amount -= 1
        else:
            return response.status_code

    raise Exception('\x1b[31m Не удалось отправить на API статус об операции. \x1b[0m ')


def get_task() -> Task:
    logging_info('Берем задание от API', set_color='blue')
    try:
        task = try_get_task()
    except Exception as e:
        logging_info(e)
        raise CouldNotGetTask from e

    token_data = task.get('token')
    operator = token_data.get('operator')
    service = token_data.get('service')

    try:
        task = Task(token=token_data.get('value'),
                    operation_id=task.get('operation'),
                    title_service=service.get('title'),
                    short_service=service.get('short_title'),
                    country=operator.get('country_code'),
                    task_id=task.get('id'),
                    operator=operator.get('title'),
                    operation_type=task.get('type'),
                    mcc=operator.get('mcc'),
                    mnc=operator.get('mnc'),
                    proxy=task.get('proxies'),
                    country_code=operator.get('country_code'))

    except TypeError as e:
        logging_error('Не удалось создать объект dataclass Task', exception=e)
        raise CouldNotGetTask from e

    logging_info('\n' +
                 f'  Взяли задание: \n '
                 f'  Сервис - {task.title_service} \n '
                 f'  Оператор - {task.operator} \n '
                 f'  Задача - {task.operation_type} \n '
                 f'  Страна - {task.country}', set_color='green')
    return task


def get_proxy(proxy_list: list) -> Proxy:
    """
    Ожидает на вход список со словарями прокси.
    Отправляем список проксей в функцию check_proxy, которая возвращает словарь с рабочей проксей,
    затем вызывает функцию prepare_proxy_address для парсинга словаря в датакласс Proxy
    """
    if len(proxy_list) == 0:
        raise IsEmptyTaskProxy

    proxy = check_proxy(proxy_list)
    logging_info(f'Взяли в работу прокси {proxy}', set_color='green')
    return prepare_proxy_address(proxy)


def check_proxy(proxy_list: list, timeout: int = 5) -> dict:
    """
    Проверяет прокси на работоспособность. Делает запрос от прокси к гуглу
    Ожидает в качестве аргумента список со словарями proxy
    Возвращает словарь с рабочим proxy
    """
    while len(proxy_list) > 0:
        proxy_item = random.choice(proxy_list)
        construct_proxy = (f"{proxy_item.get('login')}:{proxy_item.get('password')}"
                           f"@{proxy_item.get('address')}:{proxy_item.get('port')}")

        proxy_socks5 = dict(http=f"socks5://{construct_proxy}",
                            https=f"socks5://{construct_proxy}")
        try:
            requests.get('http://1.1.1.1', proxies=proxy_socks5, timeout=timeout)
        except (ConnectTimeout, ConnectionError, SSLError, ReadTimeout):
            proxy_list.remove(proxy_item)
            logging_info(f'\x1b[31m Прокси {proxy_item} не отвечает \x1b[0m ')
            continue
        else:
            return proxy_item

    raise AllProxiesDead


def prepare_proxy_address(proxy: dict) -> Proxy:
    """
    Парсит прокси login:password@addres:port в датакласс Proxy
    Функция принимает прокси в формате login:password@addres:port
    Возвращает dataclass object, с параметрами address, port, login, password
    """

    proxy_login = proxy.get('login')
    proxy_password = proxy.get('password')
    proxy_address = proxy.get('address')
    proxy_port = proxy.get('port')

    proxy = Proxy(address=proxy_address, port=proxy_port, login=proxy_login, password=proxy_password)
    return proxy
