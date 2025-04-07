import datetime
import sys


class AllProxiesDead(Exception):
    """
    Исключение возникает когда ни одно прокси взятое у API не ответило
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    '\x1b[31m'+f'Ни одно прокси полученное от API не отвечает \n {sys.exc_info()}')
        super().__init__(self.msg)


class IsEmptyTaskProxy(Exception):
    """
    Исключение возникает когда в таске приходит пустой список, без проксей
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    '\x1b[31m'+f'В задаче пришел пустой список проксей, для работы необходимо прокси \n {sys.exc_info()}')
        super().__init__(self.msg)


class CouldNotGetProxy(Exception):
    """
    Исключение возникает когда не удалось по какой либо причине взять в работу прокси
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    f'Не удалось взять в работу прокси \n {sys.exc_info()}')
        super().__init__(self.msg)


class CouldNotGetCity(Exception):
    """
    Исключение возникает когда не удалось по какой либо причине взять в работу город с координатами
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    f'Не удалось получить город от API  \n {sys.exc_info()}')
        super().__init__(self.msg)


class CouldNotGetTask(Exception):
    """
    Исключение возникает когда не удалось у API взять задание
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    f'Не удалось получить задание от API \n {sys.exc_info()}')
        super().__init__(self.msg)


class CouldNotGetDeviceBuild(Exception):
    """
    Исключение возникает когда не удалось у API взять устройство
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                   f' Не удалось получить сборку устройства от API \n {sys.exc_info()}')
        super().__init__(self.msg)


class CouldNotGetName(Exception):
    """
    Исключение возникает когда не удалось у API взять устройство
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    f'Не удалось получить от API имя \n {sys.exc_info()}')
        super().__init__(self.msg)


class FailedSendStatusOperationException(Exception):
    """
    Исключение возникает когда не удалось отправить на МАСТЕР API информацию об успешной операции
    """
    pass