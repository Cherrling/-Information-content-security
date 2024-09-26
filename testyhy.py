from DrissionPage import ChromiumOptions
from DrissionPage import ChromiumPage

# co=ChromiumOptions().set_browser_path(r'C:/code/CTF/train2024/chromedriver-win64/chromedriver.exe').use_system_user_path().set_user('Default')
co=ChromiumOptions().use_system_user_path().set_user('Default')
cp=ChromiumPage(co)
cp.get('https://www.baidu.com')
cp.wait(3)
cp.close()