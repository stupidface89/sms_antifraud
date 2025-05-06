import time
import random

from appium import webdriver
from api_antifraud.antifraud import Antifraud
from settings import logging_info, enable_data, disable_data, adb_command
from scenario.tools import simulate_keyboarding, find_element_move_to_and_click, find_element, try_to_load_element
from selenium.common.exceptions import NoSuchElementException
from api_master.name import Name
from api_master.task import Task, send_operation_status


def zalo_registration(driver: webdriver.Remote, task: Task, antifraud: Antifraud, name: Name) -> dict:
    driver.implicitly_wait(50)

    find_element_move_to_and_click(driver, id_element='com.zing.zalo:id/str_language_applied_en')

    time.sleep(1)

    find_element_move_to_and_click(driver, id_element='com.zing.zalo:id/btnRegisterUsingPhoneNumber')

    first_name_input = find_element(driver, id_element='com.zing.zalo:id/edtAccount')

    simulate_keyboarding(driver, first_name_input, name.first_name)

    find_element_move_to_and_click(driver, id_element='com.zing.zalo:id/btnNext')

    #request
    attempt = 3
    while find_element(driver, id_element='com.zing.zalo:id/tvError') is not None:
        if attempt == 0:
            raise NoSuchElementException
        attempt -= 1
        disable_data()
        enable_data()

        time.sleep(2)
        find_element_move_to_and_click(driver, id_element='com.zing.zalo:id/btnNext')

    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button')

    time.sleep(1)
    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button')

    find_element_move_to_and_click(driver, id_element='com.zing.zalo:id/tvCountryName')

    country_name_input = find_element(driver, id_element='com.zing.zalo:id/search_src_text')

    simulate_keyboarding(driver, country_name_input, 'ukr')

    find_element_move_to_and_click(driver, xpath='//android.widget.LinearLayout[2]/android.widget.LinearLayout/android.widget.TextView[1]')

    antifraud.get_phone()

    phone_number_input = find_element(driver, id_element='com.zing.zalo:id/etPhoneNumber')

    phone_number_input.click()

    simulate_keyboarding(driver, phone_number_input, antifraud.phone_number[3:])

    find_element_move_to_and_click(driver, id_element='com.zing.zalo:id/btnSubmitPhoneNumber')


