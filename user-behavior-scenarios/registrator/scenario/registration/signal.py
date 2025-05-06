import time
import random

from appium import webdriver
from api_antifraud.antifraud import Antifraud
from settings import logging_info

from selenium.common.exceptions import NoSuchElementException
from scenario.tools import numeric_keypad_input, find_element_move_to_and_click, find_element, simulate_keyboarding
from api_master.task import Task, send_operation_status


def signal_registration(driver: webdriver.Remote, task: Task, antifraud: Antifraud, name):
    """
    Скрипт для Signal 5.41.9
    """
    driver.implicitly_wait(30)

    find_element_move_to_and_click(driver, id_element='org.thoughtcrime.securesms:id/button')

    time.sleep(2)
    find_element_move_to_and_click(driver, id_element='android:id/button2')

    if 'Ваш номер телефону' in find_element(driver, id_element='org.thoughtcrime.securesms:id/verify_header').text:
        country = 'укра'
        logging_info('Язык Приложения Украинский')
    else:
        country = 'ukra'
        logging_info('Язык Приложения Английский')

    time.sleep(1)
    find_element_move_to_and_click(driver, id_element='org.thoughtcrime.securesms:id/country_spinner')

    logging_info('Открываем список телефонных кодов стран')
    find_country_input = find_element(driver, id_element='org.thoughtcrime.securesms:id/country_search')
    find_country_input.click()

    logging_info(f'Вводим страну {country}')
    find_country_input.send_keys(country[0:4])

    time.sleep(1)
    logging_info(f'Выбираем первый вариант из списка')
    find_element_move_to_and_click(driver, xpath='//android.widget.LinearLayout/android.widget.TextView[1]')

    phone_number_input = find_element(driver, xpath='//*[@resource-id="org.thoughtcrime.securesms:id/number"]/android.widget.LinearLayout/android.widget.EditText')
    phone_number_input.click()

    time.sleep(3)

    antifraud.get_phone()
    send_operation_status(operation_id=task.operation_id, status='started')

    time.sleep(1)
    logging_info('Вводим номер телефона в поле для регистрации')
    simulate_keyboarding(driver, phone_number_input, antifraud.phone_number[3:], press_keycode=True)

    time.sleep(3)
    find_element_move_to_and_click(driver, id_element='org.thoughtcrime.securesms:id/button')

    time.sleep(3)
    find_element_move_to_and_click(driver, id_element='android:id/button1')

    logging_info('Ждем отправки запроса смс')

    driver.implicitly_wait(20)

    attempt = 3
    while find_element(driver, id_element='org.thoughtcrime.securesms:id/code') is None and attempt > 0:
        logging_info('Поле для ввода пин кода не загрузилось, вылезла каптча или не удалось отправить запрос.')
        time.sleep(5)
        attempt -= 1
        find_element_move_to_and_click(driver, id_element='org.thoughtcrime.securesms:id/button')
        time.sleep(1)
        find_element_move_to_and_click(driver, id_element='android:id/button1')

    if attempt == 0:
        raise NoSuchElementException('\x1b[31m Вылезла каптча или не удалось отправить запрос \x1b[0m')

    driver.implicitly_wait(60)

    logging_info('\x1b[34m'+'Поле для ввода кода СМС загрузилось. \x1b[0m')

    send_operation_status(operation_id=task.operation_id, status='requested')
    sms_code = antifraud.get_sms()

    logging_info(f'Вводим код {sms_code}')

    numeric_keypad_input(driver, service='sl', code=sms_code)

    first_name_input_field = find_element(driver, id_element='org.thoughtcrime.securesms:id/given_name')

    time.sleep(2)
    logging_info(f'Вводим имя {name.first_name}')
    first_name_input_field.send_keys(name.first_name)

    time.sleep(1)
    find_element_move_to_and_click(driver, id_element='org.thoughtcrime.securesms:id/button')

    pin_code = str(random.randint(10, 99))+str(random.randint(10, 99))

    logging_info(f'Придумываем пин код - {pin_code}')
    find_element_move_to_and_click(driver, id_element='org.thoughtcrime.securesms:id/edit_kbs_pin_input')

    time.sleep(5)

    logging_info(f'Вводим пин код {pin_code}')
    pin_code_input = find_element(driver, id_element='org.thoughtcrime.securesms:id/edit_kbs_pin_input')
    simulate_keyboarding(driver, pin_code_input, pin_code, press_keycode=True)

    find_element_move_to_and_click(driver, id_element='org.thoughtcrime.securesms:id/edit_kbs_pin_confirm')

    time.sleep(4)
    logging_info(f'Вводим пин код {pin_code} повторно')
    pin_code_input = find_element(driver, id_element='org.thoughtcrime.securesms:id/edit_kbs_pin_input')
    simulate_keyboarding(driver, pin_code_input, pin_code, press_keycode=True)

    find_element_move_to_and_click(driver, id_element='org.thoughtcrime.securesms:id/edit_kbs_pin_confirm')

    time.sleep(5)
    logging_info('Ждем загрузку главной страницы приложения')
    find_element(driver, id_element='org.thoughtcrime.securesms:id/toolbar_settings_touch_area')

    data = {'phone_number': antifraud.phone_number, 'first_name': name.first_name}

    return data
