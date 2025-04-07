import time
import random

from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy, By
from api_antifraud.antifraud import Antifraud
from settings import URL_GET_RANDOM_NAME, logging_info, disable_data, enable_data
from scenario.tools import simulate_keyboarding, find_element_move_to_and_click, find_element, key_code
from selenium.common.exceptions import NoSuchElementException
from api_master.name import Name
from api_master.task import Task, send_operation_status


def telegram_registration(driver: webdriver.Remote, task: Task, antifraud: Antifraud, name: Name) -> dict:
    """
    Скрипт для версии Telegram 8.5.4
    """
    logging_info('Приложение Телеграм запущено')
    driver.implicitly_wait(10)

    find_element_move_to_and_click(driver, xpath='//android.widget.TextView[@index=4]')

    find_element_move_to_and_click(driver, xpath='//*[@text="CONTINUE"]')

    # Если вылезло контекстное меню для выбора языка, выбираем украинский
    # driver.implicitly_wait(3)
    # if find_element(driver, xpath='//*[@resource-id="android:id/content"]/android.widget.LinearLayout/android.widget.FrameLayout[2]'):
    #     logging_info('Приложение запросило выбрать язык интерфейса, выбираем Украiньска')
    #     find_element_move_to_and_click(driver, xpath='//*[@resource-id="android:id/content"]/android.widget.LinearLayout/android.widget.FrameLayout[2]/android.widget.TextView[1]')

    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button')

    # Если вылезло контекстное меню для выбора языка, выбираем украинский
    # driver.implicitly_wait(3)
    # if find_element(driver, xpath='//*[@resource-id="android:id/content"]/android.widget.LinearLayout/android.widget.FrameLayout[2]'):
    #     logging_info('Приложение запросило выбрать язык интерфейса, выбираем Украiньска')
    #     find_element_move_to_and_click(driver, xpath='//*[@resource-id="android:id/content"]/android.widget.LinearLayout/android.widget.FrameLayout[2]/android.widget.TextView[1]')

    # Вводим код страны телефона
    country_code_input = find_element(driver, xpath='//android.widget.LinearLayout/android.widget.EditText[1]')
    country_code_input.click()

    antifraud.get_phone()
    send_operation_status(operation_id=task.operation_id, status='started')

    logging_info('Вводим номер телефона в поле для регистрации')
    simulate_keyboarding(driver, country_code_input, antifraud.phone_number[:3], press_keycode=True)

    phone_number_input = find_element(driver, xpath='//android.widget.LinearLayout/android.widget.EditText[2]')
    phone_number_input.click()
    simulate_keyboarding(driver, phone_number_input, antifraud.phone_number[3:], press_keycode=True)

    logging_info("Нажимаем done для запроса проверочного кода")
    find_element_move_to_and_click(driver, xpath='//android.widget.FrameLayout[@content-desc="Done"]')

    #driver.implicitly_wait(10)
    # if find_element(driver, xpath='//*[@resource-id="android:id/content"]/android.widget.LinearLayout/android.widget.FrameLayout[2]'):
    #     logging_info('Приложение запросило выбрать язык интерфейса, выбираем Украiньска')
    #     find_element_move_to_and_click(driver, xpath='//*[@resource-id="android:id/content"]/android.widget.LinearLayout/android.widget.FrameLayout[2]/android.widget.TextView[1]')

    driver.implicitly_wait(10)

    find_element_move_to_and_click(driver, xpath='//*[@text="CONTINUE"]')
    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button')
    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_deny_button')

    # attempt = 3
    # if find_element(driver, xpath='//*[contains(@text, "Your Phone")]') is not None:
    #     disable_data()
    #     enable_data()
    #     attempt -= 1

    if find_element(driver, xpath='//*[contains(@text, "Check your Telegram messages")]') is not None:
        find_element_move_to_and_click(driver, xpath='//*[contains(@text, "Send the code as an SMS")]')

    driver.implicitly_wait(30)
    # request
    attempt = 3
    while find_element(driver, xpath='//*[contains(@text,"Phone verification")]') is None:
        if attempt == 0:
            raise NoSuchElementException('Не удалось отправить запрос на отправку смс')

        logging_info('Не удалось отправить запрос на отправку смс, переподключаем интернет', set_color='magenta')

        disable_data()
        enable_data()
        attempt -= 1

    time.sleep(150)
    find_element(driver, xpath='//*[contains(@text,"Phone verification")]')

    if find_element(driver, xpath='//*[contains(@text,"Phone verification")]') is not None:
        logging_info("Запросили у Телеграмма СМС, начинаем опрашивать API")
        driver.implicitly_wait(60)

        # Вызываем у объекта antifraud метод get_sms() для получения отправленного кода смс
        send_operation_status(operation_id=task.operation_id, status='requested')
        sms_code = antifraud.get_sms()

    else:
        raise NoSuchElementException('Не удалось отправить запрос на отправку смс')

    logging_info(f'Вводим код {sms_code}')
    for item in sms_code:
        time.sleep(1)
        driver.press_keycode(key_code(item))

    driver.find_element(AppiumBy.XPATH, '//android.widget.FrameLayout[@content-desc="Done"]').click()

    logging_info(f'Взяли имя {name.first_name}')
    logging_info(f'Вводим имя')

    first_name_input = find_element(driver, xpath='//*[@text="First name (required)"]')
    first_name_input.send_keys(name.first_name)
    time.sleep(5)

    driver.find_element(AppiumBy.XPATH, '//android.widget.FrameLayout[@content-desc="Done"]').click()

    # Если вылезло контекстное меню для выбора языка, выбираем украинский
    # driver.implicitly_wait(10)
    # if find_element(driver, xpath='//*[@resource-id="android:id/content"]/android.widget.LinearLayout/android.widget.FrameLayout[2]'):
    #     logging_info('Приложение запросило выбрать язык интерфейса, выбираем Украiньска')
    #     find_element_move_to_and_click(driver, xpath='//*[@resource-id="android:id/content"]/android.widget.LinearLayout/android.widget.FrameLayout[2]/android.widget.TextView[1]')

    driver.implicitly_wait(60)

    driver.find_element(AppiumBy.XPATH, '//*[@text="NOT NOW"]').click()

    driver.find_element(AppiumBy.ID, 'com.android.permissioncontroller:id/permission_deny_button').click()

    # Возвращаем данные о созданном аккаунте на сервер
    data = {'phone_number': antifraud.phone_number, 'first_name': name.first_name}

    logging_info(f'Успешная регистрация на номер {antifraud.phone_number}')

    return data
