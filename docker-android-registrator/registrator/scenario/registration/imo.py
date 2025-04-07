import time
import random

from appium import webdriver
from api_antifraud.antifraud import Antifraud
from api_antifraud.exceptions import SmsNotReceivedException

from settings import logging_info, enable_data, disable_data
from scenario.tools import simulate_keyboarding, find_element_move_to_and_click, find_element
from selenium.common.exceptions import NoSuchElementException
from api_master.name import Name
from api_master.task import Task, send_operation_status
from scenario.tools import cyrillic_translate


def imo_registration(driver: webdriver.Remote, task: Task, antifraud: Antifraud, name: Name) -> dict:
    driver.implicitly_wait(20)

    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button', raise_exception=False)

    time.sleep(1)
    find_element_move_to_and_click(driver, xpath='//android.widget.FrameLayout/android.view.ViewGroup/android.widget.LinearLayout[1]/android.widget.TextView', raise_exception=False)

    time.sleep(2)

    find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/btn_cancel', raise_exception=False)

    time.sleep(1)
    country_cody_input = find_element(driver, id_element='com.imo.android.imoim:id/country_code')

    antifraud.get_phone()
    send_operation_status(operation_id=task.operation_id, status='started')

    if country_cody_input.text != antifraud.phone_number[:3]:
        country_cody_input.clear()
        country_cody_input.click()
        logging_info(f'Вводим код страны {antifraud.phone_number[:3]}')
        simulate_keyboarding(driver, country_cody_input, antifraud.phone_number[:3], press_keycode=True)

    logging_info(f'Вводим номер телефона {antifraud.phone_number[3:]}')
    phone_number_input = find_element(driver, id_element='com.imo.android.imoim:id/phone')
    phone_number_input.click()

    simulate_keyboarding(driver, phone_number_input, antifraud.phone_number[3:], press_keycode=True)

    time.sleep(2)

    logging_info('Отправляем номер телефона')
    find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/get_started_button')

    time.sleep(1)
    find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/agree_continue')

    time.sleep(1)
    find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/btn_positive', raise_exception=False)

    time.sleep(1)
    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button', raise_exception=False)

    time.sleep(1)
    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button', raise_exception=False)

    # request
    driver.implicitly_wait(30)
    #
    # find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/btn_positive', raise_exception=False)
    #
    # find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button')
    #
    # logging_info('Запрещаем чтение истории звонков')
    # find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button')

    # request
    attempt = 2
    while find_element(driver, id_element='com.imo.android.imoim:id/new_sms_code_input') is None:
        logging_info('Элемент для ввода кода из смс не найден')
        if attempt == 0:
            raise NoSuchElementException

        time.sleep(5)
        attempt -= 1
        disable_data()
        enable_data()

    send_operation_status(operation_id=task.operation_id, status='requested')
    sms_code = antifraud.get_sms(counter=12, raise_exception=False)

    if sms_code is None:
        logging_info('СМС код не пришел, запрашиваем снова', set_color='blue')
        find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/button')
        sms_code = antifraud.get_sms(counter=15, raise_exception=True)

    time.sleep(5)
    sms_code_input = find_element(driver, id_element='com.imo.android.imoim:id/new_sms_code_input')
    sms_code_input.click()

    logging_info('Вводим СМС код')
    simulate_keyboarding(driver, sms_code_input, sms_code, press_keycode=True)

    # request
    attempt = 2
    while find_element(driver, id_element='com.imo.android.imoim:id/reg_name') is None:
        logging_info('Элемент для ввода имени не найден')
        if attempt == 0:
            raise NoSuchElementException

        time.sleep(5)
        attempt -= 1
        disable_data()
        enable_data()

    logging_info('Вводим имя')
    first_name_input = find_element(driver, id_element='com.imo.android.imoim:id/reg_name')
    first_name_input.click()

    name.first_name = cyrillic_translate(name.first_name)
    simulate_keyboarding(driver, first_name_input, name.first_name, press_keycode=True)

    #first_name_input.send_keys(name.first_name)

    # request
    time.sleep(2)
    find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/reg_done')

    time.sleep(3)
    find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/reg_done')

    time.sleep(3)
    find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/reg_done')

    # requests
    logging_info('Запрещаем чтение контактов')
    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button')
    find_element_move_to_and_click(driver, id_element='com.imo.android.imoim:id/btn_cancel')

    # time.sleep(2)
    # find_element_move_to_and_click(driver, id_element='//android.widget.LinearLayout/android.view.ViewGroup[1]')
    #
    # time.sleep(3)
    # find_element_move_to_and_click(driver, id_element='//android.widget.LinearLayout/android.view.ViewGroup[2]')
    #
    # time.sleep(3)
    # find_element_move_to_and_click(driver, id_element='//android.widget.LinearLayout/android.view.ViewGroup[3]')

    time.sleep(15)
    return {'phone_number': antifraud.phone_number, 'first_name': name.first_name}
