import time
import random

from appium import webdriver
from api_antifraud.antifraud import Antifraud
from settings import logging_info, enable_data, disable_data, adb_command
from scenario.tools import simulate_keyboarding, find_element_move_to_and_click, find_element, try_to_load_element
from selenium.common.exceptions import NoSuchElementException
from api_master.name import Name
from api_master.task import Task, send_operation_status


def onexbet_registration(driver: webdriver.Remote, task: Task, antifraud: Antifraud, name: Name) -> dict:
    driver.implicitly_wait(30)

    time.sleep(30)
    attempt = 5
    while find_element(driver, id_element='org.xbet.client1:id/app_version') is not None:
        if attempt == 0:
            raise NoSuchElementException
        attempt -= 1
        time.sleep(10)

    driver.implicitly_wait(10)
    logging_info('Приложение загрузилось')
    if find_element(driver, id_element='org.xbet.client1:id/btnUpdateContainer').text is not None:

        logging_info('Необходимо обновить приложение, запускаем через интент')
        adb_command(['shell', 'su', '0', 'am', 'start', '-n',
                     'org.xbet.client1/org.xbet.client1.presentation.activity.AppActivity'])
    time.sleep(3)

    driver.implicitly_wait(40)
    # request
    attempt = 3
    while find_element(driver, id_element='org.xbet.client1:id/registration_button') is None:
        if attempt == 0:
            raise NoSuchElementException
        attempt -= 1
        disable_data()
        enable_data()

    logging_info('Главный экран приложения загрузился, начинаем регистрацию')
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/registration_button')
    time.sleep(3)

    driver.implicitly_wait(30)
    attempt = 3
    # request
    while find_element(driver, xpath='//androidx.cardview.widget.CardView[2]') is None:
        if attempt == 0:
            raise NoSuchElementException
        disable_data()
        enable_data()
        time.sleep(10)
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/registration_button', raise_exception=False)

    find_element_move_to_and_click(driver, xpath='//androidx.cardview.widget.CardView[2]')

    # request
    country_code_input = try_to_load_element(driver, id_element='org.xbet.client1:id/country_info', attempts=3)

    if country_code_input.text != '+380':
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/country_info')
        phone_code_input = find_element(driver, id_element='org.xbet.client1:id/tv_add_manually')
        simulate_keyboarding(driver, phone_code_input, '380', press_keycode=True)
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/tv_add')

    antifraud.get_phone()

    send_operation_status(operation_id=task.operation_id, status='started')

    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/phone_body')
    phone_number_input = find_element(driver,
                                      xpath='//android.widget.LinearLayout[2]/android.widget.FrameLayout/android.widget.EditText')

    logging_info('Вводим номер телефона')
    simulate_keyboarding(driver, phone_number_input, antifraud.phone_number[3:], press_keycode=True)

    time.sleep(2)
    logging_info('Соглашаемся с политикой конфиденциальности, ставим чекбокс')
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/ready_for_anything_checkbox')

    time.sleep(2)

    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/fab')

    time.sleep(20)
    attempt = 5

    while find_element(driver, id_element='org.xbet.client1:id/app_progress') is not None:
        driver.implicitly_wait(60)

        if attempt == 0:
            raise NoSuchElementException

        disable_data()
        enable_data()
        attempt -= 1

        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/fab', raise_exception=False)

        driver.implicitly_wait(15)
        if find_element(driver, id_element='org.xbet.client1:id/app_progress') is None:
            find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/fab')

    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button')

    time.sleep(3)

    driver.implicitly_wait(25)
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button')

    # request
    attempt = 5
    while find_element(driver, id_element='org.xbet.client1:id/sms_code') is None:
        if attempt == 0:
            raise NoSuchElementException

        attempt -= 1
        disable_data()
        enable_data()
        time.sleep(20)

        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button', raise_exception=False)

    sms_code_input = find_element(driver, id_element='org.xbet.client1:id/sms_code')

    send_operation_status(operation_id=task.operation_id, status='requested')

    sms_code = antifraud.get_sms()

    sms_code_input.click()
    simulate_keyboarding(driver, sms_code_input, sms_code, press_keycode=True)

    time.sleep(2)
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button')

    driver.implicitly_wait(45)
    # request
    attempt = 5
    while find_element(driver, id_element='org.xbet.client1:id/copy') is None:
        if attempt == 0:
            raise NoSuchElementException

        attempt -= 1
        disable_data()
        enable_data()
        driver.implicitly_wait(10)
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button', raise_exception=False)

    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/copy')

    driver.implicitly_wait(5)

    time.sleep(5)
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/btnNext')

    time.sleep(2)
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/btn_skip', raise_exception=False)

    time.sleep(2)
    random_card = random.randint(2, 6)
    find_element_move_to_and_click(driver,
                                   xpath=f'//androidx.recyclerview.widget.RecyclerView/androidx.cardview.widget.CardView[{random_card}]',
                                   raise_exception=False)

    time.sleep(5)

    return {'phone_number': antifraud.phone_number, 'first_name': name.first_name}
