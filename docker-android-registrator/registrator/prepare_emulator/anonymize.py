import logging


def change_gsm_properties(self):
    """
    Меняет gsm параметры устройства:
        1) iso-код страны
    """
    self._adb_command(['-s', self.device, 'shell', 'su', 'setprop gsm.sim.operator.iso-country', 'ua'])


def anonymize(self):
    """
    Выполняет ряд методов, которые подменяют параметры устройства на
    указанные, для достижения "анонимизации" устройства
    """
    self._change_gsm_properties()
    logging.info('Create config file')

