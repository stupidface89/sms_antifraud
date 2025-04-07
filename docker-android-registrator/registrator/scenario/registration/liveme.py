import time
import random

from appium import webdriver
from api_antifraud.antifraud import Antifraud
from settings import logging_info, enable_data, disable_data
from scenario.tools import simulate_keyboarding, find_element_move_to_and_click, find_element, generate_password
from selenium.common.exceptions import NoSuchElementException
from api_master.name import Name
from api_master.task import Task, send_operation_status


def liveme_registration(driver: webdriver.Remote, antifraud: Antifraud, task: Task, name: Name) -> dict:

    driver.implicitly_wait(30)

    logging_info('Нажимаем кнопку Agree')
    find_element_move_to_and_click(driver, id_element='com.plusme.live:id/es')

    if find_element(driver, id_element='com.plusme.live:id/hpx').text != '380':
        find_element_move_to_and_click(driver, id_element='com.plusme.live:id/hpx')
        country_field_input = find_element(driver, id_element='android:id/search_src_text')
        country_field_input.click()

        logging_info(f'Находим страну ukraine в списке')
        time.sleep(2)
        country_field_input.send_keys('ukra')
        find_element_move_to_and_click(driver, xpath='//android.widget.FrameLayout/android.view.ViewGroup/android.widget.ListView/android.widget.LinearLayout/android.widget.FrameLayout')

    antifraud.get_phone()
    logging_info('Вводим номер телефона')
    phone_number_input = find_element(driver, 'com.plusme.live:id/bin')
    phone_number_input.click()
    simulate_keyboarding(driver, phone_number_input, antifraud.phone_number[3:], press_keycode=True)

    find_element_move_to_and_click(driver, id_element='com.plusme.live:id/wj')

    # request
    attempt = 3
    while find_element(driver, id_element='com.plusme.live:id/dos') is None:
        if attempt == 0:
            raise NoSuchElementException
        disable_data()
        enable_data()
        attempt -= 1
        find_element_move_to_and_click(driver, id_element='com.plusme.live:id/wj')

    if find_element(driver, id_element='com.plusme.live:id/dos') is not None:
        sms_code = antifraud.get_sms(counter=45)

        sms_code_input = find_element(driver, id_element='com.plusme.live:id/dos')
        simulate_keyboarding(driver, sms_code_input, sms_code, press_keycode=sms_code)

    # request
    password = generate_password()
    password_input = find_element(driver, id_element='com.plusme.live:id/bil')
    password_input.click()

    logging_info(f'Вводим придуманный пароль {password}')

    simulate_keyboarding(driver, password_input, password, press_keycode=True)
    find_element_move_to_and_click(driver, id_element='com.plusme.live:id/wj')

    time.sleep(60)
