import requests
import json
import time

from .exceptions import CouldNotGetDeviceBuild
from requests.exceptions import RequestException
from settings import URL_GET_DEVICE, logging_error
from dataclasses import dataclass


@dataclass()
class DeviceBuild:
    fingerprint: str
    retail_model: str
    manufacturer: str
    model: str
    product: str
    brand: str
    hardware: str
    device: str
    board: str
    user: str
    display: str
    id: str
    type: str
    tags: str
    bootloader: str
    cpu_abi: str
    cpu_abi2: str
    radio_version: str
    host: str
    version_incremental: str


def try_get_build(amount: int = 5, timeout: float = 2.0) -> DeviceBuild:
    while amount > 0:
        amount -= 1

        try:
            device_build = requests.get(URL_GET_DEVICE, timeout=timeout)
        except RequestException:
            time.sleep(5)
            continue

        if device_build.status_code != 200:
            time.sleep(5)
            continue

        try:
            device_build = device_build.json()
        except AttributeError as e:
            logging_error('Не удалось преобразовать ответ со сборкой устройства в JSON', exception=e)
            raise CouldNotGetDeviceBuild from e

        retail_model = device_build['device'].get('retail_model')

        device_build = device_build['build_device']

        return DeviceBuild(fingerprint=device_build.get('FINGERPRINT'),
                           retail_model=retail_model,
                           manufacturer=device_build.get('MANUFACTURER'),
                           model=device_build.get('MODEL'),
                           product=device_build.get('PRODUCT'),
                           brand=device_build.get('BRAND'),
                           hardware=device_build.get('HARDWARE'),
                           device=device_build.get('DEVICE'),
                           board=device_build.get('BOARD'),
                           user=device_build.get('USER'),
                           display=device_build.get('DISPLAY'),
                           id=device_build.get('ID'),
                           type=device_build.get('TYPE'),
                           tags=device_build.get('TAGS'),
                           bootloader=device_build.get('BOOTLOADER'),
                           cpu_abi=device_build.get('CPU_ABI'),
                           cpu_abi2=device_build.get('CPU_ABI2'),
                           radio_version=device_build.get('radio_version'),
                           host=device_build.get('HOST'),
                           version_incremental=device_build.get('VERSION_INCREMENTAL')
                           )

    raise CouldNotGetDeviceBuild
