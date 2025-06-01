import os
import threading
import urllib.request
import time
import logging
import tempfile
import shutil
from typing import Optional
import base64
import numpy as np
import cv2

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

# Module-level constants for timeouts
WEBDRIVER_PAGELOAD_TIMEOUT = 30  # seconds
SCRIPT_TIMEOUT_SECONDS = 30  # seconds


class HeadlessBrowser:
    WEBDRIVER_TIMEOUT = WEBDRIVER_PAGELOAD_TIMEOUT
    SCRIPT_TIMEOUT = SCRIPT_TIMEOUT_SECONDS

    WEBDRIVER_ARGUMENTS = (
        '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
        '--window-size=1366,768', '--incognito', '--ignore-certificate-errors',
        '--disable-extensions', '--disable-application-cache', '--disk-cache-size=0',
        '--media-cache-size=0', '--aggressive-cache-discard',
        '--disable-offline-load-stale-cache', '--disable-cache',
        '--disable-setuid-sandbox', '--disable-infobars', '--disable-popup-blocking',
        '--disable-notifications', '--disable-default-apps', '--disable-component-update',
        '--disable-sync', '--disable-domain-reliability', '--disable-remote-fonts',
        '--disable-speech-api', '--hide-scrollbars', '--mute-audio', '--no-first-run',
        '--no-zygote', '--no-default-browser-check', '--dns-prefetch-disable',
        '--disable-background-networking', '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows', '--disable-breakpad',
        '--disable-client-side-phishing-detection',
        '--disable-component-extensions-with-background-pages',
        '--disable-features=TranslateUI,OptimizationHints,MediaRouter,DialMediaRouteProvider',
        '--disable-hang-monitor', '--disable-ipc-flooding-protection',
        '--disable-prompt-on-repost', '--disable-renderer-backgrounding',
        '--force-color-profile=srgb', '--metrics-recording-only',
        '--password-store=basic', '--use-mock-keychain',
        '--enable-logging=stderr', '--log-level=3',  # Changed to 3 (FATAL) for Chrome's internal logs
        '--disable-blink-features=AutomationControlled',
    )

    def __init__(self, useragent: Optional[str] = None,
                 disable_javascript: bool = False,
                 headless: bool = True,
                 page_load_strategy: str = 'eager'):
        # Only one INFO log for successful init, or CRITICAL for failure.
        chrome_options = webdriver.ChromeOptions()

        valid_strategies = ['normal', 'eager', 'none']
        if page_load_strategy.lower() in valid_strategies:
            chrome_options.page_load_strategy = page_load_strategy.lower()
        else:
            # This is a deviation, so a warning might be acceptable.
            logging.warning(f"Invalid page_load_strategy '{page_load_strategy}', defaulting to 'eager'.")
            chrome_options.page_load_strategy = 'eager'

        for opt in self.WEBDRIVER_ARGUMENTS:
            chrome_options.add_argument(opt)

        if headless:
            chrome_options.add_argument('--headless=new')

        prefs = {
            "download.prompt_for_download": True,
            "download.directory_upgrade": True,
            "safeBrowse.enabled": True,
            "safeBrowse.downloads.enabled": True,
        }
        self.download_dir = tempfile.mkdtemp(prefix="headless_downloads_")
        prefs["download.default_directory"] = self.download_dir
        chrome_options.add_experimental_option("prefs", prefs)

        system_proxies = urllib.request.getproxies()
        if system_proxies:
            http_proxy_url = system_proxies.get('http') or system_proxies.get('https')
            if http_proxy_url:
                chrome_options.add_argument(f'--proxy-server={http_proxy_url}')

        chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])
        chrome_options.add_experimental_option('useAutomationExtension', False)

        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)

            self.driver.set_page_load_timeout(self.WEBDRIVER_TIMEOUT)
            self.driver.set_script_timeout(self.SCRIPT_TIMEOUT)

            try:
                self.driver.execute_cdp_cmd('Page.setDownloadBehavior',
                                            {'behavior': 'deny', 'downloadPath': self.download_dir})
            except Exception:  # Fail silently or minimal warning for non-critical CDP
                logging.debug("CDP download deny command failed (suppressed warning).")

            if disable_javascript:
                try:
                    self.driver.execute_cdp_cmd("Emulation.setScriptExecutionDisabled", {"value": True})
                except Exception:  # Fail silently or minimal warning
                    logging.debug("CDP JavaScript disable command failed (suppressed warning).")

            ua_to_set = useragent
            if not ua_to_set:
                try:
                    original_ua = self.driver.execute_script('return navigator.userAgent')
                    ua_to_set = original_ua.replace('HeadlessChrome', 'Chrome').replace('Headless', '')
                except Exception:
                    ua_to_set = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            try:
                self.driver.execute_cdp_cmd('Network.setUserAgentOverride', {'userAgent': ua_to_set})
            except Exception:  # Fail silently or minimal warning
                logging.debug("CDP User-Agent override failed (suppressed warning).")

            logging.info(f"HeadlessBrowser (id: {id(self)}) initialized.")

        except Exception as e:
            logging.critical(f"HeadlessBrowser (id: {id(self)}) CRITICAL FAILURE to initialize: {e}", exc_info=True)
            self._cleanup_download_dir()
            raise RuntimeError(f"WebDriver initialization failed: {e}") from e

    def _cleanup_download_dir(self):
        if hasattr(self, 'download_dir') and os.path.exists(self.download_dir):
            try:
                shutil.rmtree(self.download_dir)
            except Exception as e_rmdir:
                logging.warning(f"Could not remove temp download dir '{self.download_dir}': {e_rmdir}")
            finally:
                if hasattr(self, 'download_dir'):
                    delattr(self, 'download_dir')

    def get_page_source_with_timeout(self, url: str) -> Optional[str]:
        if not self.is_alive(): return None
        try:
            self.driver.get(url)
            return self.driver.page_source
        except TimeoutException:
            logging.warning(f"Page load timed out for {url}")
            return None
        except Exception as e:
            logging.error(f"Error loading page source for {url}: {e.msg if isinstance(e, WebDriverException) else e}")
            return None

    def get_screenshot_as_png(self, screenshot_timeout: int = 15) -> Optional[tuple]:
        """
        Returns a tuple: (grayscale_image: np.ndarray, screenshot_base64: str)
        - grayscale_image: for OpenCV comparison
        - screenshot_base64: for UI display
        """
        if not self.is_alive():
            logging.error("Driver not alive for screenshot.")
            return None

        result = {"png": None, "exception": None}

        def try_screenshot_in_thread():
            try:
                result["png"] = self.driver.get_screenshot_as_png()
            except Exception as e:
                result["exception"] = e

        thread = threading.Thread(target=try_screenshot_in_thread)
        thread.start()
        thread.join(timeout=screenshot_timeout)

        if thread.is_alive():
            logging.warning(f"Screenshot call timed out after {screenshot_timeout}s.")
            return None
        if result["exception"]:
            logging.error(
                f"Screenshot failed: {result['exception'].msg if isinstance(result['exception'], WebDriverException) else result['exception']}")
            return None
        if not result.get("png"):
            logging.warning("Screenshot returned empty bytes without explicit error.")
            return None

        png_bytes = result.get("png")

        # Decode color image
        color_image = cv2.imdecode(np.frombuffer(png_bytes, np.uint8), cv2.IMREAD_COLOR)

        # Convert to grayscale for processing
        gray_image = cv2.cvtColor(color_image, cv2.COLOR_BGR2GRAY)

        # Encode color image for base64 (UI)
        _, buffer = cv2.imencode('.png', color_image)
        screenshot_base64 = base64.b64encode(buffer).decode('utf-8')

        return gray_image, screenshot_base64

    def safe_visit_and_screenshot(self, url: str, screenshot_path: str) -> bool:
        # This method implies a file operation, success/failure is important.
        if not self.is_alive(): return False
        try:
            self.driver.get(url)
        except TimeoutException:
            logging.warning(f"Timeout loading {url} for screenshot.")
            return False
        except Exception as e:
            logging.error(f"Error loading {url} for screenshot: {e.msg if isinstance(e, WebDriverException) else e}")
            return False

        result = self.get_screenshot_as_png()
        if result:
            _, screenshot_base64 = result
            png_data = base64.b64decode(screenshot_base64)
            with open(screenshot_path, 'wb') as f:
                f.write(png_data)
            return True

        return False

    def is_alive(self) -> bool:
        if not hasattr(self, 'driver') or self.driver is None:
            return False
        try:
            _ = self.driver.window_handles
            return True
        except Exception:  # Any exception means it's not reliably alive
            return False

    def stop(self):
        logging.info(f"Stopping HeadlessBrowser (id: {id(self)})...")
        if hasattr(self, 'driver') and self.driver:
            try:
                handles = list(self.driver.window_handles)
                for handle in handles:
                    try:
                        self.driver.switch_to.window(handle)
                        self.driver.close()
                    except Exception:
                        pass
            except Exception:
                pass  # Ignore errors getting handles if driver is already failing
            finally:
                try:
                    self.driver.quit()
                except Exception as e_quit:
                    logging.warning(f"Exception during driver.quit (id: {id(self)}): {e_quit}")
                finally:
                    self.driver = None
        self._cleanup_download_dir()
        # logging.info(f"HeadlessBrowser (id: {id(self)}) stopped.") # Redundant if stop() start is logged

    def __del__(self):
        # __del__ should generally not have logging unless debugging GC issues.
        # self.stop() will be called and has its own minimal logging.
        self.stop()

    def new_tab(self, url: str):
        if not self.is_alive():
            # This is an operational error if called when not alive.
            logging.error("Driver not alive, cannot open new tab for {url}.")
            raise WebDriverException(f"Driver not alive. Cannot open new tab for {url}.")
        try:
            initial_handles = set(self.driver.window_handles)
            self.driver.execute_script("window.open(arguments[0], '_blank');", url)
            time.sleep(0.75)

            new_handles = set(self.driver.window_handles) - initial_handles
            if new_handles:
                self.driver.switch_to.window(new_handles.pop())
            else:
                logging.warning(f"No new tab detected for {url}, attempting load in current/last tab.")
                if self.driver.window_handles:
                    self.driver.switch_to.window(self.driver.window_handles[-1])
                    self.driver.get(url)
                else:
                    # This state should ideally be caught by is_alive()
                    logging.error(f"No window handles available to open URL {url} (driver claims alive).")
                    raise WebDriverException("No window handles available to open URL.")
        except Exception as e:
            logging.error(f"Error opening new tab for {url}: {e.msg if isinstance(e, WebDriverException) else e}")
            # Attempt cleanup only if driver seems to be in a state where it's possible
            if self.is_alive() and self.driver.window_handles:
                self.close_current_tab_and_switch(0)
            raise

    def close_current_tab_and_switch(self, target_index: int = 0):
        if not self.is_alive(): return  # Silently return if not alive
        try:
            num_handles = len(self.driver.window_handles)
            if num_handles == 0: return  # Silently return if no tabs

            if num_handles > 0: self.driver.close()
            time.sleep(0.1)

            handles_after_close = self.driver.window_handles
            if handles_after_close:
                actual_idx = min(max(0, target_index), len(handles_after_close) - 1)
                self.driver.switch_to.window(handles_after_close[actual_idx])
            # No log for successful close/switch in minimal mode.
        except Exception as e:
            # Log only if an unexpected error occurs during close/switch.
            logging.warning(f"Error closing/switching tab: {e.msg if isinstance(e, WebDriverException) else e}")