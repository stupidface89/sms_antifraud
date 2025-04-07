import time
import requests
import json

from api_master.task import Task
from settings import logging_info, logging_error
from requests.exceptions import ConnectionError, ConnectTimeout
from .exceptions import (SmsNotReceivedException, FailedGetPhoneNumber, DifferentStatusResponseException,
                         FailedToGetActivityStatus, NoNumbersAtTheMoment, FailedToSentStatus)


class Antifraud(object):
    def __init__(self, task: Task, operation_id=None):
        self.operation_id = operation_id
        self.short_service = task.short_service
        self.phone_number = None
        self.operation_id = None
        self.sms_code = None
        self.country = 1
        self.api_token = task.token
        self.url = f'https://api.antifraudsms.com/stubs/handler_api.php?api_key={self.api_token}'

    def _request_sms(self):
        """
        Отправляем запрос на сервер для получения смс.
        Возвращает текстовое значение.
        """

        if self.operation_id is not None:
            url_get_sms = f'{self.url}&action=getStatus&id={self.operation_id}'
        else:
            raise Exception('Не указан id операции, для запроса смс')

        try:
            response = requests.get(url_get_sms, timeout=10)
        except (ConnectionError, ConnectTimeout) as e:
            logging_error(f'Не удалось получить код из смс', exception=e)
        else:
            return response.text

    def _request_phone(self, delay=30, attempts_count=3) -> str:
        """
        Отправляем запрос за сервер для получения номера телефона для
        соответствующего сервиса и страны.
        Возвращает текстовое значение. Опрашивает сервер пока не получит
        ответ, с интервалом в 30 секунд. attempts_count = Количество попыток,
        после которых вызывается соответствующее исключение
        """
        url_get_phone = f'{self.url}&action=getNumber&service={self.short_service}&country={self.country}'

        while attempts_count > 0:
            try:
                response = requests.get(url_get_phone, timeout=10)
            except (ConnectionError, ConnectTimeout) as e:
                attempts_count -= 1
                time.sleep(delay)
                logging_error(f'Не удалось получить телефон у антифрод.', exception=e)
            else:
                return response.text

        raise FailedGetPhoneNumber

    def _send_status(self, status_code, delay=30, attempts_count=3):
        while attempts_count > 0:
            url_send_status = f'{self.url}&action=setStatus&status={status_code}&id={self.operation_id}'
            try:
                response = requests.get(url_send_status, timeout=10).text
            except (ConnectionError, ConnectTimeout) as e:
                attempts_count -= 1
                time.sleep(delay)
                logging_error(f'Не удалось отправить статус антифроду', exception=e)
            else:
                return response
        raise FailedToGetActivityStatus

    def _read_sms(self):
        """
        Получаем ответ от метода request_sms, если в ответе нет смс,
        опрашиваем сервер снова с задержкой в 5 секунд.
        attempt_count = Количество попыток, после которых вызывается
        соответствующее исключение
        """

        response = self._request_sms()
        response = response.split(':')

        if response[0] == 'STATUS_OK':
            sms_code = response[1]
            return sms_code

        elif response[0] == 'STATUS_WAIT_CODE':
            logging_info(f'STATUS_WAIT_CODE')

        else:
            logging_info(f'Не удалось получить смс, некорректный ответ от API\n {response}')

    def get_phone(self, delay: int = 30, attempts_count: int = 5) -> dict:
        logging_info('Запрашиваем номер телефона у Антифрода', set_color='blue')

        while attempts_count > 0:
            if self.phone_number is not None:
                return self.phone_number

            response = self._request_phone()
            response = response.split(':')

            if response[0] == 'ACCESS_NUMBER':
                logging_info('\x1b[32m' + f'Взяли в работу - {response[-1]}, id операции - {response[-2]} \x1b[0m ')

                self.phone_number = response[-1]
                self.operation_id = response[-2]
                return dict(phone_number=str(response[-1]),
                            operation_id=response[-2])
            elif response[0] == 'NO_NUMBERS':
                logging_info(f'{response[0]} У антифрода закончились на текущий момент номера, пробуем взять снова',
                             set_color='magenta')
                raise NoNumbersAtTheMoment

            else:
                attempts_count -= 1
                time.sleep(delay)
                logging_info(f'Не удалось получить номер телефона у антифрода. {response}')
        raise FailedGetPhoneNumber

    @staticmethod
    def _json_account_data(account_data: dict):
        # !!!! Требуется рефакторинг на обработку None при получении значений из словаря!
        """
        Принимает словарь с данными об аккаунте, и формирует из них json для
        дальнейшей отправки на API.
        birth_day должен быть в формате 21-05-1991
        """

        #login = account_data.get('login')
        #password = account_data.get('password')
        phone_number = account_data.get('phone_number')
        #birth_day = account_data.get('birth_day')
        first_name = account_data.get('first_name')

        #if login is None:
        #    login = account_data.get('phone_number')

        # Формируем данные об аккаунте
        json_data = {#"login": login,
                     "phone": phone_number,
                     #"password": password,
                     "parameters": {
                         "user_agent": "",
                         "proxy": "",
                         "first_name": first_name,
                         "last_name": "",
                         #"birthday": birth_day,
                         "email_login": "",
                         "email_password": "",
                         "cookies": []
                     }}

        return json.dumps(json_data)

    def send_status(self, status_code):
        """
        1 - сообщить о готовности номера (смс на номер отправлено)
        3 - запросить еще один код
        6 - сообщить об успешной активации, завершить работу с номером
        8 - сообщить о том, что номер не использован в активации.
            Завершить активацию с ошибкой (если смс получена, но аккаунт не создан - отдавать этот статус)
        """
        logging_info(f'Отравляем статус - {status_code} на Антифрод', set_color='blue')
        try:
            response = self._send_status(status_code=status_code)
        except FailedToSentStatus as e:
            logging_error(e.msg, exception=e)
            raise

        logging_info(response)

        # Проверяем, как сервер отвечает на наши статусы
        if status_code == 1 and response != 'ACCESS_READY':
            raise DifferentStatusResponseException

        elif status_code == 3 and response != 'ACCESS_RETRY_GET':
            raise DifferentStatusResponseException

        elif status_code == 6 and response != 'ACCESS_ACTIVATION':
            raise DifferentStatusResponseException

        elif status_code == 8 and response != 'ACCESS_CANCEL':
            raise DifferentStatusResponseException

    def send_account_data(self, account_data: dict):
        logging_info(f'Отправляем на Антифрод сведения об аккаунте')
        account_data = self._json_account_data(account_data)
        url_send_account_data = f'{self.url}&action=sendAccount&id={self.operation_id}&account={account_data}'

        try:
            response = requests.get(url_send_account_data, timeout=10)
            logging_info(response.text)
        except (ConnectionError, ConnectTimeout) as e:
            logging_error('Не удалось отправить данные об аккаунт на API антифрод', exception=e)

    def get_sms(self, delay: int = 5, counter: int = 20, raise_exception: bool = True):
        """
        Вызывает метод _wait_sms вызывается counter количество раз, пока не
        получит в результате текст из смс. Если код не получили вызываем
        исключение
        """
        if self.sms_code is not None:
            return self.sms_code

        self.send_status(1)
        time.sleep(2)
        logging_info('Запрашиваем смс')

        while counter > 0:
            sms_code = self._read_sms()

            if sms_code is not None:
                logging_info(f'Получили код из смс {sms_code}')
                self.sms_code = sms_code
                return sms_code

            time.sleep(delay)
            counter -= 1

        if not raise_exception:
            return None

        raise SmsNotReceivedException
