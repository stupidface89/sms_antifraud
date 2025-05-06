import time
import random
import string

from typing import NoReturn
from settings import logging_info, disable_data, enable_data

from appium.webdriver.common.appiumby import AppiumBy
from appium.webdriver.common.touch_action import TouchAction

from selenium.webdriver.common.actions import interaction
from selenium.webdriver.common.actions.action_builder import ActionBuilder
from selenium.webdriver.common.actions.pointer_input import PointerInput

from selenium.common.exceptions import NoSuchElementException, WebDriverException
from selenium.webdriver.common.action_chains import ActionChains


def digits_keyboard_coords(service, digit):
    """
    Возвращает координаты кнопки на цифровой клавиатуре, подходит для:
        Telegram = tg,
        Signal = sl,
        Bolt = bl,
    """
    if service == 'tg':
        digits_coords = {
            '1': [135, 1675],
            '2': [435, 1675],
            '3': [735, 1675],
            '4': [135, 1845],
            '5': [435, 1845],
            '6': [735, 1845],
            '7': [135, 2000],
            '8': [435, 2000],
            '9': [735, 2000],
            '0': [435, 2155]
        }
        return digits_coords[digit]

    elif service == 'sl':
        digits_coords = {
            '1': [175, 1385],
            '2': [535, 1385],
            '3': [895, 1385],
            '4': [175, 1600],
            '5': [535, 1600],
            '6': [895, 1600],
            '7': [175, 1815],
            '8': [535, 1815],
            '9': [895, 1815],
            '0': [535, 2030]
        }
        return digits_coords[digit]

    elif service == 'sl_little_keyboard':
        digits_coords = {
            '1': [300, 1525],
            '2': [560, 1525],
            '3': [825, 1525],
            '4': [300, 1665],
            '5': [560, 1665],
            '6': [825, 1665],
            '7': [300, 1810],
            '8': [560, 1810],
            '9': [825, 1810],
            '0': [520, 1955]
        }

        return digits_coords[digit]


def numeric_keypad_input(driver, service: str, code: str):
    for item in code:
        '''
        Реализация через TouchActionj
        '''
        # logging_info(f'Нажимаем на цифровой клавиатуре цифру {item}')
        #
        # TouchAction(driver).tap(x=digits_keyboard_coords(service=service, digit=item)[0],
        #                         y=digits_keyboard_coords(service=service, digit=item)[1], count=1).perform()

        '''
        ----- ====== :::: Реализация через w3c не работает в докере! Тех.долг !!
        '''
        time.sleep(random.uniform(0.6, 1.1))
        actions = ActionChains(driver)
        actions.w3c_actions = ActionBuilder(driver, mouse=PointerInput(interaction.POINTER_TOUCH, "touch"))
        actions.w3c_actions.pointer_action.move_to_location(x=digits_keyboard_coords(service=service, digit=item)[0],
                                                            y=digits_keyboard_coords(service=service, digit=item)[1])
        actions.w3c_actions.pointer_action.click()
        actions.w3c_actions.perform()


def generate_password():
    length = random.randint(8, 10)
    uppercase = random.choice(string.ascii_uppercase)
    chars = 'abcdefghjklmnpqrstuvwxyz'
    digits = '1234567890'
    return (uppercase +
            ''.join(random.choice(chars) for _ in range(length - 3)) +
            ''.join(random.choice(digits) for _ in range(3)))


def find_request_permit(driver, deny=True):
    """
    Проверяет есть ли на странице запрос на пермит, если есть, то по умолчанию
    даёт отказ в диалоговом окне на запрос
    """
    if driver.find_element(AppiumBy.ID, 'com.android.permissioncontroller:id/permission_deny_button') is not None:
        if deny:
            driver.find_element(AppiumBy.ID,
                               'com.android.permissioncontroller:id/permission_deny_button').click()
        else:
            driver.find_element(AppiumBy.ID,
                                'com.android.permissioncontroller:id/permission_allow_button').click()


def try_to_load_element(driver, id_element=None, xpath=None, attempts: int = 5, time_waiting: int = 20):
    if id_element is None and xpath is None:
        raise Exception('Нужно передать ID или XPATH элемента')

    if id_element is not None and xpath is not None:
        raise Exception('Были переданы ID и XPATH. Необходимо указать лишь '
                        'один селектор')

    driver.implicitly_wait(time_waiting)

    if id_element is not None:
        while find_element(driver, id_element=id_element) is None:
            if attempts == 0:
                raise NoSuchElementException

            disable_data()
            enable_data()

            attempts -= 1
        return find_element(driver, id_element=id_element)

    else:
        while find_element(driver, xpath=xpath) is None:
            if attempts == 0:
                raise NoSuchElementException

            disable_data()
            enable_data()

            attempts -= 1

        return find_element(driver, xpath=xpath)


def find_element(driver, id_element=None, xpath=None):
    if id_element is None and xpath is None:
        raise Exception('Нужно передать ID или XPATH элемента')

    if id_element is not None and xpath is not None:
        raise Exception('Были переданы ID и XPATH. Необходимо указать лишь '
                        'один селектор')

    if xpath is not None:
        try:
            element = driver.find_element(AppiumBy.XPATH, xpath)
        except NoSuchElementException:
            logging_info(f'[!] Не был найден элемент {xpath}, продолжаем выполнение сценария')
            return None

        else:
            return element

    if id_element is not None:
        try:
            element = driver.find_element(AppiumBy.ID, id_element)
        except NoSuchElementException:
            logging_info(f'[!] Не был найден элемент {id_element}, продолжаем выполнение сценария')
            return None

        else:
            return element


def find_element_move_to_and_click(driver, id_element=None, xpath=None, raise_exception=True):
    if id_element is None and xpath is None:
        raise Exception('Нужно передать ID или XPATH элемента')

    if id_element is not None and xpath is not None:
        raise Exception('Были переданы ID и XPATH. Необходимо указать лишь один селектор')

    if xpath is not None:
        try:
            element = driver.find_element(AppiumBy.XPATH, xpath)
        except (NoSuchElementException, WebDriverException):
            logging_info(f'[!] Не был найден элемент {xpath}, продолжаем выполнение сценария')

            if raise_exception:
                raise

        else:
            time.sleep(random.uniform(0.3, 1.0))
            ActionChains(driver).move_to_element(element).click().perform()

    elif id_element is not None:
        try:
            element = driver.find_element(AppiumBy.ID, id_element)
        except NoSuchElementException:
            logging_info(f'[!] Не был найден элемент {id_element}, продолжаем выполнение сценария')

            if raise_exception:
                raise

        else:
            time.sleep(random.uniform(0.3, 1.0))
            ActionChains(driver).move_to_element(element).click().perform()


def key_code(value):
    """
    Возвращает цифру или букву, которая соответствует коду клавиши
    """
    key_codes = {'0': 7, '1': 8, '2': 9, '3': 10, '4': 11, '5': 12, '6': 13, '7': 14, '8': 15, '9': 16,
                 'a': 29, 'A': 29, 'b': 30, 'B': 30, 'c': 31, 'C': 31, 'd': 32, 'D': 32, 'e': 33, 'E': 33,
                 'f': 34, 'F': 34, 'g': 35, 'G': 35, 'h': 36, 'H': 36, 'i': 37, 'I': 37, 'j': 38, 'J': 38,
                 'k': 39, 'K': 39, 'l': 40, 'L': 40, 'm': 41, 'M': 41, 'n': 42, 'N': 42, 'o': 43, 'O': 43,
                 'p': 44, 'P': 44, 'q': 45, 'Q': 45, 'r': 46, 'R': 46, 's': 47, 'S': 47, 't': 48, 'T': 48,
                 'u': 49, 'U': 49, 'v': 50, 'V': 50, 'w': 51, 'W': 51, 'x': 52, 'X': 52, 'y': 53, 'Y': 53,
                 'z': 54, 'Z': 54}

    return key_codes[value]


def simulate_keyboarding(driver, input_element, text: str, press_keycode=False):
    """
    Реализовано через два метода ввода текста:
        1) Через send_keys, set_value
        2) Через press_keycode
    """
    for item in text:
        delay = random.uniform(0.6, 1.1)

        if not press_keycode:
            input_element.set_value(item)

        else:
            driver.press_keycode(key_code(item))
        time.sleep(delay)


def cyrillic_translate(value):
    result = ''
    legend = {'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e',
              'ё': 'yo', 'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k',
              'л': 'l', 'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r',
              'с': 's', 'т': 't', 'у': 'u', 'ф': 'f', 'х': 'h', 'ц': 'ts',
              'ч': 'ch', 'ш': 'sh', 'щ': 'sh', 'ъ': 'y', 'ы': 'y', 'ь': '',
              'э': 'e', 'ю': 'yu', 'я': 'ya', 'А': 'A', 'Б': 'B', 'В': 'V',
              'Г': 'G', 'Д': 'D', 'Е': 'E', 'Ё': 'Yo', 'Ж': 'Zh', 'З': 'Z',
              'И': 'I', 'Й': 'Y', 'К': 'K', 'Л': 'L', 'М': 'M', 'Н': 'N',
              'О': 'O', 'П': 'P', 'Р': 'R', 'С': 'S', 'Т': 'T', 'У': 'U',
              'Ф': 'F', 'Х': 'H', 'Ц': 'Ts', 'Ч': 'Ch', 'Ш': 'Sh', 'Щ': 'Sh',
              'Ъ': 'Y', 'Ы': 'Y', 'Ь': '', 'Э': 'E', 'Ю': 'Yu', 'Я': 'Ya'}

    if not value:
        return None

    for item in value:
        result += legend[item]

    return result


def generate_email():
    domens_list = ['@mail.ru', '@i.ua', '@meta.ua', '@outlook.com', '@online.ua']

    random_domen = random.choice(domens_list)
    length = random.randint(5, 8)
    random_digit = str(random.randint(10, 99))
    letters = string.ascii_lowercase

    return (''.join(random.choice(letters) for _ in range(length))
            + random_digit + random_domen)
