# config.py

import os
import re

# Default values for environment-based configurations
REQUEST_TIMEOUT_DNS = float(os.environ.get('REQUEST_TIMEOUT_DNS', 2.5))
REQUEST_RETRIES_DNS = int(os.environ.get('REQUEST_RETRIES_DNS', 2))
REQUEST_TIMEOUT_HTTP = float(os.environ.get('REQUEST_TIMEOUT_HTTP', 5))
REQUEST_TIMEOUT_SMTP = float(os.environ.get('REQUEST_TIMEOUT_SMTP', 5))
WEBDRIVER_PAGELOAD_TIMEOUT = float(os.environ.get('WEBDRIVER_PAGELOAD_TIMEOUT', 12.0))

# Other constants
VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)')
USER_AGENT_STRING = f'Mozilla/5.0 ({os.sys.platform} {os.sys.maxsize.bit_length() + 1}-bit) dnstwist/1.0'
THREAD_COUNT_DEFAULT = min(32, os.cpu_count() + 4)

# --- Configuration Constants ---
BROWSER_ACTION_DELAY: int = int(os.getenv("BROWSER_ACTION_DELAY", 2))  # Delay for page rendering
MAX_WORKERS_PROCESSING: int = int(os.getenv("MAX_WORKERS_PROCESSING", 1)) # Default to 1 for Selenium thread safety
                                                                          # with a single browser instance.