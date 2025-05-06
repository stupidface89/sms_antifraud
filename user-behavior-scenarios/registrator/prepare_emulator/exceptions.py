import datetime


class CouldNotPrepareDevice(Exception):
    """
    Исключение возникает когда не удается по какой либо причине запустить эмулятор
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    'Не удалось подготовить к работе устройство')
        super().__init__(self.msg)


class CouldNotStartEmulator(Exception):
    """
    Исключение возникает когда не удается по какой либо причине запустить эмулятор
    """
    def __init__(self, msg=None):
        if msg:
            self.msg = msg
        else:
            self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                        'Устройство по какой то причине не смогло запуститься')

        super().__init__(self.msg)


class DeviceNotFoundException(Exception):
    """
    Исключение возникает когда небыло найдено ни одного эмулятора для запуска
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    'Устройство для запуска эмулятора не найдено')
        super().__init__(self.msg)


class FridaScenarioDoesntExist(Exception):
    """
    Вызываем исключение когда пытаемся вызвать несуществующий сценарий фриды для сервиса
    """
    def __init__(self):
        self.msg = (f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : '
                    'Сценарий Frida для сервиса не найден')
        super().__init__(self.msg)
