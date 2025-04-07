import time

from selenium.common.exceptions import NoSuchElementException

from appium import webdriver
from api_antifraud.antifraud import Antifraud
from api_master.name import Name
from api_master.task import Task, send_operation_status
from settings import logging_info, logging_error, URL_GET_RANDOM_NAME, disable_data, enable_data

from scenario.tools import (simulate_keyboarding, find_element_move_to_and_click, find_element, generate_email)


def bolt_registration(driver: webdriver.Remote, task: Task, antifraud: Antifraud, name: Name):
    driver.implicitly_wait(30)

    logging_info('Разрешаем приложению доступ к геоданным')
    find_element_move_to_and_click(driver, id_element='com.android.permissioncontroller:id/permission_allow_foreground_only_button')

    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/phoneInputField')

    if find_element(driver, id_element='ee.mtakso.client:id/phonePrefixContainer') is not None:
        find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/phonePrefixContainer')
        find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/hint')

    else:
        find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/phonePrefixFlag')
        find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/hint')

    search_country_input = find_element(driver, xpath='//android.widget.FrameLayout/android.view.ViewGroup/android.widget.LinearLayout/android.widget.FrameLayout/android.widget.EditText')
    search_country_input.click()
    simulate_keyboarding(driver, search_country_input, 'ukraine'[:4])

    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/countryName')

    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/phoneInputField')

    time.sleep(2)
    phone_number_input = find_element(driver, id_element='ee.mtakso.client:id/phoneInputField')

    antifraud.get_phone()
    send_operation_status(operation_id=task.operation_id, status='started')

    phone_number_input.click()
    simulate_keyboarding(driver, phone_number_input, antifraud.phone_number[3:])

    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/continueButton')
    time.sleep(10)

    attempt = 5
    driver.implicitly_wait(35)
    while find_element(driver, id_element='ee.mtakso.client:id/confirmCodeInput') is None:
        if attempt == 0:
            raise NoSuchElementException
        disable_data()
        enable_data()
        attempt -= 1
        find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/primaryButton')
        find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/continueButton')

    driver.implicitly_wait(15)
    sms_code_input = find_element(driver, id_element='ee.mtakso.client:id/confirmCodeInput')

    send_operation_status(operation_id=task.operation_id, status='requested')
    sms_code = antifraud.get_sms()

    sms_code_input.click()

    logging_info(f'Вводим код {sms_code}')
    simulate_keyboarding(driver, sms_code_input, sms_code)

    driver.implicitly_wait(35)

    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/continueWithEmail')
    email_input = find_element(driver, xpath='//*[@resource-id="ee.mtakso.client:id/signupEmailInput"]/android.widget.EditText')
    email_input.click()

    email = generate_email()
    logging_info(f'Вводим почту {email}')
    email_input.send_keys(email)
    #simulate_keyboarding(driver, input_element=email_input, text=email)

    logging_info('Отправляем почту')
    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/continueButton')

    attempt = 8
    driver.implicitly_wait(35)

    while find_element(driver, xpath='//*[@resource-id="ee.mtakso.client:id/firstNameInput"]/android.widget.EditText') is None:
        logging_info('Не удалось отправить почтy, пробуем снова')

        # Что-то с интернетом
        driver.implicitly_wait(10)
        if find_element(driver, 'ee.mtakso.client:id/primaryButton') is not None:
            if attempt == 0:
                raise NoSuchElementException
            logging_info('Пропал интернет')
            disable_data()
            enable_data()
            attempt -= 2
            find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/primaryButton')
            find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/continueButton')
        else:
            # Не принял придуманную почту
            logging_info('Болт не принял адрес почты')
            email = generate_email()
            email_input = find_element(driver, xpath='//*[@resource-id="ee.mtakso.client:id/signupEmailInput"]/android.widget.EditText')
            email_input.clear()
            email_input.click()
            logging_info(f'Вводим почту {email}')
            email_input.send_keys(email)
            #simulate_keyboarding(driver, input_element=email_input, text=email)
            attempt -= 1
            find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/continueButton')

    driver.implicitly_wait(35)
    first_name_input = find_element(driver, xpath='//*[@resource-id="ee.mtakso.client:id/firstNameInput"]/android.widget.EditText')
    first_name_input.click()
    simulate_keyboarding(driver, input_element=first_name_input, text=name.first_name)

    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/lastNameInput')

    last_name_input = find_element(driver, xpath='//*[@resource-id="ee.mtakso.client:id/lastNameInput"]/android.widget.EditText')
    last_name_input.click()
    simulate_keyboarding(driver, input_element=last_name_input, text=name.last_name)

    time.sleep(3)
    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/doneButton')

    driver.implicitly_wait(5)
    time.sleep(3)
    find_element_move_to_and_click(driver, id_element='ee.mtakso.client:id/setManuallyBtn', raise_exception=False)

    # Возвращаем данные о созданном аккаунте на сервер
    data = {'phone_number': antifraud.phone_number,
            'first_name': name.first_name,
            'last_name': name.first_name,
            'email': email}

    logging_info(f'Успешная регистрация на номер {antifraud.phone_number}')

    time.sleep(10)

    return data



