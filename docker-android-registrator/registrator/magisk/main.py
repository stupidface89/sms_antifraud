import time

from settings import MAGISK_PATH, logging_error, logging_info, adb_command
from exception import FailedMagiskScenario

from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from selenium.common.exceptions import WebDriverException, NoSuchElementException
from selenium.webdriver.common.action_chains import ActionChains
from urllib3.exceptions import MaxRetryError


def magisk_scenario(self):
    """
    Изменяем параметры магиска - работа без запроса на разрешения действий от root.
    """
    desired_caps = {
        "platformName": "Android",
        "platformVersion": "10",
        "automationName": "UiAutomator2",
        "app": MAGISK_PATH,
        "appPackage": "com.topjohnwu.magisk",
        "appActivity": "com.topjohnwu.magisk.ui.MainActivity",
        "fullReset": False,
        "clearSystemFiles": False,
        "deviceName": self.device
    }

    try:
        driver = webdriver.Remote(f'http://127.0.0.1:4723/wd/hub',
                                  desired_capabilities=desired_caps)

    except (WebDriverException, MaxRetryError) as e:
        logging_error(f'Не удалось выполнить сценарий с Magisk', exception=e)
        raise FailedMagiskScenario
    else:
        # Ждём элементы до 20 секунд
        driver.implicitly_wait(20)

        try:
            cancel_button = driver.find_element(AppiumBy.ID, 'com.topjohnwu.magisk:id/dialog_base_button_3')
        except NoSuchElementException:
            logging_info(
                f'[!] Элемент "//com.topjohnwu.magisk:id/dialog_base_button_3" не был найден\nПродолжаем выполнение')
        else:
            ActionChains(driver).move_to_element(cancel_button).click().perform()

        # Нажимаем на шестерёнку
        settings_button = driver.find_element(AppiumBy.XPATH, '//android.widget.TextView[@content-desc="Settings"]')
        ActionChains(driver).move_to_element(settings_button).click().perform()

        driver.swipe(start_x=75, start_y=1300, end_x=75, end_y=0, duration=1000)
        driver.swipe(start_x=75, start_y=1300, end_x=75, end_y=0, duration=1000)
        time.sleep(2)

        # Нажимаем на пункт в меню настроек Automatic Response
        driver.find_element(AppiumBy.XPATH, '//*[@text="Automatic Response"]').click()

        # Выбираем вариант из контекстного меню Grant
        driver.find_element(AppiumBy.XPATH, '//android.widget.TextView[@text="Grant"]').click()
        logging_info('Настройка Magsik успешно завершена')


def install_magisk(self):
    adb_command(['install', MAGISK_PATH])