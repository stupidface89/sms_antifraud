import datetime
import sys


class UnknownServiceException(Exception):
    """
    Исключение возникает когда в сценарий в качестве атрибута был передан неизвестный сервис
    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                        '\x1b[31m' + f'Был получен в работу неизвестный для сценария сервис  {sys.exc_info()} \x1b[0m')

        super().__init__(self.msg)


class CouldNotCreateAppiumDriverException(Exception):
    """
    Исключение возникает когда по какой то причине не удается создать драйвер соединения с Appium
    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                        '\x1b[31m' + f'Не удалось создать связь с сервером Appium \n {sys.exc_info()} \x1b[0m')
            super().__init__(self.msg)


class FailedCompleteScenarioException(Exception):
    """
    Исключение возникает когда не удается выполнить сценарий
    """
    def __init__(self, msg=None):
        if msg is None:
            self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                        '\x1b[31m' + f'Не удалось выполнить сценарий  \n {sys.exc_info()} \x1b[0m')
        super().__init__(self.msg)
