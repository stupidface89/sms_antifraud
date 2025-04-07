import time
import random


from appium import webdriver
from api_antifraud.antifraud import Antifraud
from settings import logging_info, enable_data, disable_data
from scenario.tools import simulate_keyboarding, find_element_move_to_and_click, find_element
from selenium.common.exceptions import NoSuchElementException
from api_master.name import Name
from api_master.task import Task, send_operation_status


def zenly_registration(driver: webdriver.Remote,
                       antifraud: Antifraud,
                       task: Task,
                       name: Name) -> dict:

    driver.implicitly_wait(30)
    time.sleep(2)
    find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/signup_intro_signup')

    time.sleep(2)
    first_name_input = find_element(driver, id_element='app.zenly.locator:id/signup_name_username')
    logging_info(f'Вводим имя {name.first_name}')
    first_name_input.send_keys(name.first_name)

    find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/signup_name_next_button')

    birthday = {'day': str(random.randint(1, 28)), 'month': str(random.randint(1, 12)), 'year': str(random.randint(1978, 2002))}
    logging_info(f'Вводим дату рождения {birthday.get("day") + "." + birthday.get("month") + "." + birthday.get("year")}')

    birthday_day_input = find_element(driver, id_element='app.zenly.locator:id/age_value')
    birthday_month_input = find_element(driver, id_element='app.zenly.locator:id/age_value_2')
    birthday_year_input = find_element(driver, id_element='app.zenly.locator:id/age_value_3')

    time.sleep(2)
    birthday_day_input.send_keys(birthday.get('day'))

    time.sleep(2)
    birthday_month_input.send_keys(birthday.get('month'))

    time.sleep(2)
    birthday_year_input.send_keys(birthday.get('year'))

    find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/country_picker_button')

    find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/background')

    country_find_input = find_element(driver, id_element='app.zenly.locator:id/view_input')
    country_find_input.click()

    time.sleep(1)
    country_find_input.send_keys('укра')

    time.sleep(2)
    find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/country_name')

    antifraud.get_phone()
    send_operation_status(operation_id=task.operation_id, status='started')

    phone_number_input = find_element(driver, id_element='app.zenly.locator:id/phone_picker_number')

    phone_number_input.click()

    logging_info(f'Вводим номер телефона {antifraud.phone_number}')
    time.sleep(2)
    simulate_keyboarding(driver, phone_number_input, antifraud.phone_number[3:])

    logging_info('Отправляем телефон')
    find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/phone_picker_next')

    attempt = 4
    driver.implicitly_wait(20)

    while find_element(driver, id_element='app.zenly.locator:id/code_input') is None:
        if attempt == 0:
            raise NoSuchElementException

        logging_info('Не удалось отправить телефон, пробуем снова')
        disable_data()
        enable_data()
        find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/dialog_button_primary')
        find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/phone_picker_next')
        logging_info('Пробуем отправить телефон снова')
        attempt -= 1

    driver.implicitly_wait(10)

    logging_info('СМС была запрошена, начинаем опрашивать у API код из смс')
    driver.implicitly_wait(5)

    # Увеличиваем время ожидания смс для оператора Inter
    send_operation_status(operation_id=task.operation_id, status='requested')

    if task.operator in ['IT']:
        logging_info(f'Оператор {task.operator}', set_color='yellow')
        sms_code = antifraud.get_sms(counter=35)
    else:
        sms_code = antifraud.get_sms()

    logging_info(f'Вводим код {sms_code}')

    time.sleep(1)
    index = 1
    for item in sms_code:
        first_code_input = find_element(driver, xpath=f'//*[@resource-id="app.zenly.locator:id/code_input"]/android.widget.EditText[{index}]')
        first_code_input.click()
        logging_info(f'Вводим {item}')
        first_code_input.send_keys(item)
        index += 1

    attempt = 4

    # request
    driver.implicitly_wait(20)
    while find_element(driver, id_element='app.zenly.locator:id/btn_request_ignore_battery_optimizations') is None:
        if attempt == 0:
            raise NoSuchElementException

        disable_data()
        enable_data()

        logging_info('\x1b[35m'+'Не удалось отправить код, вводим снова'+'\x1b[0m')
        find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/dialog_button_primary')

        logging_info('Вводим заново код из смс')
        index = 1

        for item in sms_code:
            first_code_input = find_element(driver,
                                            xpath=f'//*[@resource-id="app.zenly.locator:id/code_input"]/android.widget.EditText[{index}]')
            first_code_input.click()
            logging_info(f'Вводим {item}')
            first_code_input.send_keys(item)
            index += 1

        attempt -= 1

    driver.implicitly_wait(30)

    logging_info('\x1b[32m'+'Код из СМС отправлен'+'\x1b[0m')

    time.sleep(5)
    logging_info('Нажимаем на кнопку разрешения запуска приложения в фоне')

    if find_element(driver, id_element='app.zenly.locator:id/btn_request_ignore_battery_optimizations') is not None:
        find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/btn_request_ignore_battery_optimizations')
    else:
        find_element_move_to_and_click(driver, id_element='//android.widget.FrameLayout[2]/android.view.ViewGroup/android.widget.TextView[2]')

    driver.implicitly_wait(10)
    time.sleep(3)
    logging_info('Даем разрешение на пермишен, отвечаем Allow')
    find_element_move_to_and_click(driver, id_element='android:id/button1')

    if find_element(driver, id_element='app.zenly.locator:id/btn_request_ignore_battery_optimizations') is not None:
        logging_info('Повторно Нажимаем на кнопку разрешения запуска приложения в фоне')
        find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/btn_request_ignore_battery_optimizations')
        logging_info('Повторно Даем разрешение на пермишен, отвечаем Allow')
        find_element_move_to_and_click(driver, id_element='android:id/button1')

    find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/btn_locate_me')

    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_allow_foreground_only_button')

    logging_info('Даем разрешение на доступ к контактам')
    find_element_move_to_and_click(driver, id_element='app.zenly.locator:id/contact_permission_button')
    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_allow_button')

    time.sleep(10)
    return {'phone_number': antifraud.phone_number, 'first_name': name.first_name}
