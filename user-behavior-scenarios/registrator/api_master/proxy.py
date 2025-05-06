import time

import requests
import json
import random
import logging

from dataclasses import dataclass, field
from requests.exceptions import RequestException, ConnectTimeout, ConnectionError, SSLError, ReadTimeout

from api_master.task import Task, Proxy
from settings import logging_error, logging_info
from .exceptions import AllProxiesDead, CouldNotGetProxy


# deprecated
def try_get_proxy(amount: int = 5, timeout: float = 2.0) -> json:
    while amount > 0:
        try:
            proxy_set = requests.get(URL_GET_PROXY, timeout=timeout)
        except RequestException as e:
            amount -= 1
            continue

        if proxy_set.status_code != 200:
            time.sleep(5)
            continue

        return proxy_set.text

    time.sleep(10)
    raise CouldNotGetProxy


# deprecated
def get_proxy() -> Proxy:
    """
    Делает запрос к API и получает список объектов прокси, с соответствующими параметрами.
    Вызывает check_proxy для проверки прокси
    Возвращает уже проверенное, живое dataclass Proxy
    """

    logging_info('\x1b[34m Запрашиваем прокси у API \x1b[0m ')
    try:
        proxy_set = try_get_proxy()
    except CouldNotGetProxy as e:
        logging_info('\x1b[31m' + e.msg + '\x1b[0m ')
        raise

    proxy_set = json.loads(proxy_set)
    alive_proxy = check_proxy(proxy_list=proxy_set)

    logging_info(f'\x1b[32m Взяли в работу прокси - {alive_proxy} \x1b[0m ')

    return prepare_proxy_address(alive_proxy)


# deprecated
def prepare_proxy_address() -> Proxy:
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


# deprecated
def check_proxy(proxy_list: list, timeout: int = 5) -> dict:
    """
    Проверяет прокси на работоспособность. Делает запрос от прокси к гуглу
    Ожидает в качестве аргумента список со словарями proxy
    Возвращает словарь с рабочим proxy
    """
    while len(proxy_list) > 0:
        proxy_item = random.choice(proxy_list)
        construct_proxy = f"{proxy_item.get('login')}:{proxy_item.get('password')}@{proxy_item.get('address')}:{proxy_item.get('port')}"

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
