from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait

class AwsEntWebLogin:

    def run(self):
        debug_port = 9222
        tab_url = "https://eu-north-1.signin.aws.amazon.com"
        page_load_timeout = 9
        title = "Amazon Web Services Sign-in"

        chrome_options = Options()
        chrome_options.add_experimental_option('debuggerAddress', f'127.0.0.1:{debug_port}')

        driver = webdriver.Chrome(options=chrome_options)
        driver.execute_script(f'window.open("{tab_url}","_blank");')

        if self.__switch_tab(driver, title):
            wait = WebDriverWait(driver, page_load_timeout)
            button = wait.until(EC.visibility_of_element_located((By.XPATH, '//button[.//span[text()="Sign in"]]')))
            button.submit()
        else:
            print('Could find necessary element on the page')

    @staticmethod
    def __switch_tab(driver, title):
        driver.switch_to.window(driver.window_handles[len(driver.window_handles)-1])
        if driver.title.casefold() == title.casefold():
            return True

        for handle in driver.window_handles:
            driver.switch_to.window(handle)
            if driver.title.casefold() == title.casefold():
                return True

        return False
