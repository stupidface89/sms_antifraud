import time

import requests
import json

from dataclasses import dataclass
from requests.exceptions import RequestException

from settings import URL_GET_RANDOM_CITY, logging_info
from .exceptions import CouldNotGetCity


@dataclass
class City:
    title: str
    region: str
    latitude: float
    longitude: float


def try_get_city(amount: int = 5, timeout: float = 2.0) -> json:
    while amount > 0:
        try:
            get_city = requests.get(URL_GET_RANDOM_CITY, timeout=timeout)
        except RequestException as e:
            amount -= 1
            continue

        if get_city.status_code != 200:
            time.sleep(5)
            continue

        return get_city.text

    time.sleep(10)
    raise CouldNotGetCity


def get_city() -> City:
    logging_info('Запрашиваем город и координаты у API',set_color='blue')
    city = json.loads(try_get_city())
    logging_info(f'Взяли в работу город {city.get("title")} - {city.get("region")}, '
                 f'{city.get("latitude")}, {city.get("longitude")}', set_color='green')

    return City(title=city.get('title'),
                region=city.get('region'),
                latitude=city.get('latitude'),
                longitude=city.get('longitude'))

