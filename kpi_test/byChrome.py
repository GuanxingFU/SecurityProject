from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.firefox.options import Options

# Path to ChromeDriver (adjust this to the location of your chromedriver)
# chromedriver_path = "path/to/chromedriver"

# Set up Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")  # Run in headless mode
chrome_options.add_argument("--disable-gpu")  # Disable GPU (for stability)
chrome_options.add_argument("--no-sandbox")  # Needed for some environments
chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome resource limits
chrome_options.add_argument("--log-level=3")  # Reduce logging
# Uncomment for headless mode (no browser UI)
# chrome_options.add_argument("--headless")

# Initialize WebDriver
# service = Service(chromedriver_path)
# driver = webdriver.Chrome(service=service, options=chrome_options)
# driver = webdriver.Chrome( options=chrome_options)
driver = webdriver.Firefox( options=chrome_options)
for i in range(100):
    try:
        # Open a webpage
        # url = "https://blog.note.lat"
        url = "https://blog-ech-inner.note.lat/"
        driver.get(url)
        print("Yes")



    finally:
        # Close the browser
        # driver.quit()
        fool = 1
driver.quit()


