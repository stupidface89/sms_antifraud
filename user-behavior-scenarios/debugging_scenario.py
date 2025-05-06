import logging
import time
import os
import random
import pytz

os.environ['MASTER_API_URL'] = 'http://192.168.0.15:8000'

from selenium.common.exceptions import NoSuchElementException
from datetime import datetime
from appium import webdriver
from api_master.task import get_task
from prepare_emulator.main import Emulator
from scenario.tools import simulate_keyboarding, find_element_move_to_and_click, find_element, try_to_load_element
from api_antifraud.antifraud import Antifraud

from api_master.task import get_task, send_operation_status, Task, Proxy, get_proxy
from api_master.name import Name, get_name

from api_master.device_build import try_get_build, DeviceBuild

from settings import adb_command, disable_wifi, disable_data, enable_data
from settings import logging_info, logging_error


def onexbet_registration(driver: webdriver.Remote, task: Task, name: Name):
    driver.implicitly_wait(30)

    if find_element(driver, id_element='org.xbet.client1:id/title').text == "Update available":
        logging_info('Необходимо обновить приложение, запускаем интент')
        adb_command(['shell', 'su', '0', 'am', 'start', '-n', 'org.xbet.client1/org.xbet.client1.presentation.activity.AppActivity'])
    time.sleep(3)

    # request
    attempt = 3
    while find_element(driver, id_element='org.xbet.client1:id/registration_button') is None:
        if attempt == 0:
            raise NoSuchElementException
        attempt -= 1
        disable_data()
        enable_data()

    logging_info('Приложение запустилось, начинаем регистрацию')
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/registration_button')

    time.sleep(3)

    attempt = 3
    # request
    while find_element(driver, xpath='//androidx.cardview.widget.CardView[2]') is None:
        if attempt == 0:
            raise NoSuchElementException
        disable_data()
        enable_data()
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/registration_button')

    find_element_move_to_and_click(driver, xpath='//androidx.cardview.widget.CardView[2]')

    # request
    country_code_input = try_to_load_element(driver, id_element='org.xbet.client1:id/country_info')

    if country_code_input.text != '+380':
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/country_info')
        phone_code_input = find_element(driver, id_element='org.xbet.client1:id/tv_add_manually')
        simulate_keyboarding(driver, phone_code_input, '380', press_keycode=True)
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/tv_add')

    phone_number = '380987255175'

    send_operation_status(operation_id=task.operation_id, status='started')

    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/phone_body')
    phone_number_input = find_element(driver,
                                      xpath='//android.widget.LinearLayout[2]/android.widget.FrameLayout/android.widget.EditText')

    logging_info('Вводим номер телефона')
    simulate_keyboarding(driver, phone_number_input, phone_number[3:], press_keycode=True)

    time.sleep(2)
    logging_info('Соглашаемся с политикой конфиденциальности, ставим чекбокс')
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/ready_for_anything_checkbox')

    time.sleep(2)

    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/fab')

    # request
    driver.implicitly_wait(45)
    while find_element(driver, id_element='org.xbet.client1:id/action_button') is None:
        if attempt == 0:
            raise NoSuchElementException
        disable_data()
        enable_data()
        attempt -= 1
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/fab')

    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button')

    time.sleep(3)

    driver.implicitly_wait(40)
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button')

    # request
    sms_code_input = try_to_load_element(driver, id_element='org.xbet.client1:id/sms_code', time_waiting=45)

    send_operation_status(operation_id=task.operation_id, status='requested')

    sms_code = '3589'

    sms_code_input.click()
    simulate_keyboarding(driver, sms_code_input, sms_code, press_keycode=True)

    time.sleep(2)
    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button')

    # request
    attempt = 3
    while find_element(driver, id_element='org.xbet.client1:id/copy') is None:
        if attempt == 0:
            raise NoSuchElementException

        attempt -= 1
        disable_data()
        enable_data()
        driver.implicitly_wait(10)
        find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button', raise_exception=False)

    find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/copy')

    # find_element_move_to_and_click(driver, id_element='org.xbet.client1:id/action_button')
    # find_element(driver, id_element='org.xbet.client1:id/copy').click()

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


def redsocks_run(task: Task, device_build: DeviceBuild, proxy: Proxy):
    emulator = Emulator()
    emulator.run_emulator(task=task)
    #emulator.prepare(proxy=proxy, task=task, device_build=device_build)
    disable_wifi()


def capture_screenshot(driver, service) -> bool:
    current_time = datetime.now(tz=pytz.timezone('Asia/Krasnoyarsk')).strftime("%H-%M-%S %d-%m-%Y")
    image = driver.get_screenshot_as_file(f'./screenshots/{service} {current_time}.png')
    return image

def prepare_driver():
    desired_caps = {'platformName': 'Android',
                    'platformVersion': '10',
                    'automationName': 'UiAutomator2',
                    'deviceName': 'device_1',
                    'newCommandTimeout': 480,
                    'noReset': True,
                    'dontStopAppOnReset': True,
                    'autoLaunch': False,
                    'appWaitDuration': 60000,
                    'deviceReadyTimeout': 30,
                    'androidDeviceReadyTimeout': 30}

    driver = webdriver.Remote('http://0.0.0.0:4723/wd/hub', desired_capabilities=desired_caps)
    return driver


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)

    task = get_task()
    proxy = get_proxy(task.proxy)
    device_build = try_get_build()
    driver = prepare_driver()
    name = get_name()

    redsocks_run(task=task, proxy=proxy, device_build=device_build)
    onexbet_registration(driver=driver, task=task, name=name)
