import time
import logging

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec


class ParseTwitter(object):
    """
    Класс вытаскивает со страницы профиля последние X твиттов пользователя, а также авторов комментариев.
    """

    login_url = "https://twitter.com/login"
    exe_path = "./chromedriver.exe"
    service = Service(executable_path=exe_path)
    options = Options()
    logging.basicConfig(level=logging.INFO)

    def __init__(self, profile_url, silence=False):
        self.profile_url = profile_url
        self.silence = silence
        self.driver = self._tuner()

    def _tuner(self):
        """
        Задает параметры запуска WebDriver'а
        """
        if self.silence:
            self.options.add_argument('headless')

        self.options.add_argument('User-Agent=Mozilla/5.0 (Windows NT 6.1; WOW64) '
                                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/47.0.2526.111 Safari/537.36')
        self.options.add_argument("--lang=eng")
        self.options.add_argument('--disable-blink-features=AutomationControlled')

        return webdriver.Chrome(service=self.service, options=self.options)

    def _find_twit(self, index):
        """
        Ищет твит по индексу положения
        :param index: Индекс положения твита на страинце
        :return Возвращает элемент с твитом
        """
        time.sleep(0.5)
        xpath_to_twit = f"(.//section[\"aria-labelledby\"]//article[\"aria-labelledby\"])[{index}]"
        try:
            element = self.driver.find_element(By.XPATH, xpath_to_twit)

        except NoSuchElementException:
            pass
        else:
            return element

    def _focus_on_element(self, element):
        """
        Метод фокусирует положение страницы на элементе
        :param element: Элемент страницы
        """
        webdriver.ActionChains(self.driver).move_to_element(element)

    @staticmethod
    def _read_twit_message(twit):
        """
        Метод возращает сообщение твита, если текст в твите отсутствует, то возвращает --- empty twit ---
        :param twit: Элемент с твитом
        :return: Сообщение твита
        """
        xpath_to_twitter_message = "div/div/div/div/div[2]/div[2]/div[1]//span"
        message = '--- empty twit ---'

        try:
            message = twit.find_element(By.XPATH, xpath_to_twitter_message).text
        except (NoSuchElementException, AttributeError):
            pass
        finally:
            return message

    @staticmethod
    def _get_thread_url(twit):
        """
        :param twit: Элемент с твитом
        :return: Урл треда твита
        """
        xpath_to_thread_url = "div/div/div/div[2]/div[2]/div[1]/div/div/div/a"
        try:
            get_url_thread = twit.find_element(By.XPATH, xpath_to_thread_url).get_attribute('href')
        except NoSuchElementException:
            pass
        else:
            return get_url_thread

    def _open_tab(self, url):
        """
        Метод открывает новую вкладку в браузере
        :param url: Адрес сайта
        """
        self.driver.execute_script(f'window.open("{url}","_blank")')
        self.driver.switch_to.window(self.driver.window_handles[1])

    def _close_tab(self):
        """
        Метоод закрывает текущую вкладку в браузере
        """
        self.driver.close()
        self.driver.switch_to.window(self.driver.window_handles[0])

    def _take_thread_comments(self, thread_url, count_comments: int, unique_authors=True):
        """
        :param unique_authors: Если True, то метод возвращает список с уникальными авторами комментариев
        :param count_comments: Задаёт количество комментариев, профили авторов которых нужно вернуть
        :return Возвращает список с ссылками на профиль последних X авторов комментариев
        """
        # Открываем тред твита в новой вкладке
        self._open_tab(thread_url)

        WebDriverWait(self.driver, 5).until(
            ec.presence_of_element_located((By.XPATH, ".//article[@aria-labelledby]"))
        )

        profile_urls = []

        # По Селектору xpath_to_comments также находится сам твит автора, поэтому начинаем перебор с index = 2
        xpath_to_comments = '(.//article["aria-labelledby"]/div/div/div/div[2]/div[2]/div/div/div/div/div/a)'
        index = 2

        # Если количество комментариев к твиту меньше, чем нам необходимо вернуть, ограничвием условие перебора
        # количеством комментариев
        if len(self.driver.find_elements(By.XPATH, xpath_to_comments))-1 < count_comments:
            count_comments = len(self.driver.find_elements(By.XPATH, xpath_to_comments))-1

        while len(profile_urls) < count_comments:
            comment = self.driver.find_element(By.XPATH, f'{xpath_to_comments}[{index}]')
            self._focus_on_element(comment)
            profile_urls.append(comment.get_attribute('href'))
            index += 1

        if unique_authors:
            list(set(profile_urls))

        self._close_tab()
        return profile_urls[0:count_comments]

    def constructor(self, count_twits: int):
        """
        :param count_twits: Количество твитов, текст которых нужно вернуть
        """
        self.driver.get(self.profile_url)
        WebDriverWait(self.driver, 5).until(
            ec.presence_of_element_located((By.XPATH, '(.//section[@aria-labelledby])[1]'))
        )

        index = 1
        while index <= count_twits:
            time.sleep(0.5)

            # Берём твит
            twit = self._find_twit(index)

            try:
                self._focus_on_element(twit)
            except (NoSuchElementException, AttributeError):
                index += 1

            # Прокручиваем экран
            self.driver.execute_script('window.scrollBy(0, window.innerHeight)')

            message = self._read_twit_message(twit)
            url_thread = self._get_thread_url(twit)
            authors_comments = self._take_thread_comments(url_thread, count_comments=3, unique_authors=False)

            logging.info(message)
            logging.info(authors_comments)

            index += 1

        self.driver.quit()


if __name__ == "__main__":
    #twitter = ParseTwitter(profile_url="https://twitter.com/elonmusk")
    twitter = ParseTwitter(profile_url="https://twitter.com/varlamov")
    twitter.constructor(10)
