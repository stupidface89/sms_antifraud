import datetime
import sys


class SmsNotReceivedException(Exception):
    """
    Исключение возникает когда в течение определённого времени не можем
    получить СМС сообщение
    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : Не удалось получить СМС, время ожидания истекло \n {sys.exc_info()}'
            super().__init__(self.msg)


class FailedGetPhoneNumber(Exception):
    """
    Исключение возникает когда по какой-то причине антифрод не даёт номер
    телефона
    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : Не удалось взять номер телефона у API Антифрода \n {sys.exc_info()}'
            super().__init__(self.msg)


class NoNumbersAtTheMoment(Exception):
    """
    Исключение возникает когда у антифрода закончились номера
    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : На данный момент у Антифрода закончились номера \n {sys.exc_info()}'
            super().__init__(self.msg)


class DifferentStatusResponseException(Exception):
    """
    Исключение возникает когда при отпракве статуса, сервер отвечает не так
    как ожидается
    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : We are waiting different response status \n {sys.exc_info()}'
            super().__init__(self.msg)


class FailedToGetActivityStatus(Exception):
    """
    Исключение возникает когда API antifraud не отдаёт нам ответ после отправки
    статуса
    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : Не удалось получить номер телефона от API \n {sys.exc_info()}'
            super().__init__(self.msg)


class FailedToSentAccountData(Exception):
    """

    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : Не удалось отправить данные об аккаунте \n {sys.exc_info()}'
            super().__init__(self.msg)


class FailedToSentStatus(Exception):
    """

    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : Не удалось отправить статус операции на Антифрод \n {sys.exc_info()}'
            super().__init__(self.msg)