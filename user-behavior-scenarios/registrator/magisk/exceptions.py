import datetime


class FailedMagiskScenario(Exception):
    """
    Исключение возникает когда не удается по какой либо причине выполнить сценарий в Magisk
    """
    def __init__(self):
        self.msg = f' {datetime.datetime.now().time().strftime("%H:%M:%S")} : Не удалось выполнить сценарий с Magisk'
        super().__init__(self.msg)