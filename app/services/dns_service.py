import base64
import concurrent
import json
import logging
import os
import queue
import threading
import time
from collections import defaultdict
from io import BytesIO
from typing import List, Optional, Dict, Any, Tuple
import numpy as np
from PIL import Image
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

# --- Configure Logging ---
# Get the root logger
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO) # Set overall default to INFO or higher

# Remove any existing handlers from the root logger to prevent duplicate output
# This is crucial if you've already configured logging elsewhere or if default handlers exist
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)


# Suppress specific noisy loggers
# Set these to WARNING, ERROR, or CRITICAL to silence DEBUG and INFO messages
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('selenium.webdriver.remote.remote_connection').setLevel(logging.WARNING)

# If you're using webdriver_manager, you can also suppress its logs:
# from webdriver_manager.core.logger import __logger as wdm_logger
# wdm_logger.setLevel(logging.WARNING)
# os.environ['WDM_LOG'] = '0' # Another way to silence webdriver_manager

# --- Selenium Setup ---
options = Options()
# Suppress the "DevTools listening on ws://..." message
options.add_experimental_option('excludeSwitches', ['enable-logging'])
# Set the log level for the ChromeDriver executable itself (most effective for driver's own logs)
options.add_argument('--log-level=3') # 0=INFO, 1=WARNING, 2=LOG_ERROR, 3=LOG_FATAL (only fatal errors)

# Redirect ChromeDriver service log output to null
# On Windows, use 'NUL'. On Unix-like systems (Linux/macOS), use '/dev/null'.
service_log_path = os.devnull
if os.name == 'nt': # Check if it's Windows
    service_log_path = 'NUL'

service = Service(log_output=service_log_path)


# Assuming app.config.dconfig and app.config.redis_config are in the python path
# If not, you might need to adjust imports or provide dummy values for these constants
try:
    from app.config.dconfig import BROWSER_ACTION_DELAY, MAX_WORKERS_PROCESSING
    from app.config.redis_config import redis_client, THROTTLE_DELAY_SECONDS, WHOIS_CACHE_EXPIRY_SECONDS
except ImportError:
    # Provide default values if config files are not found (for standalone execution)
    logging.warning("Could not import app config. Using default values.")
    BROWSER_ACTION_DELAY = 2
    MAX_WORKERS_PROCESSING = 10  # Default if not imported
    redis_client = None  # No caching if redis_client is None
    THROTTLE_DELAY_SECONDS = 1
    WHOIS_CACHE_EXPIRY_SECONDS = 86400  # 1 day

from app.services.fuzzer import Fuzzer
from app.services.headless_browser import HeadlessBrowser
from app.services.whois import Whois
from app.utils.domain_util import convert_dates_to_strings, convert_strings_to_dates, domain_tld
import cv2
from bs4 import BeautifulSoup
import requests
from skimage.metrics import structural_similarity as ssim
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from fuzzywuzzy import fuzz


FINAL_RESULT_CACHE_PREFIX = "phishing_result:"
FINAL_RESULT_CACHE_EXPIRY_SECONDS = WHOIS_CACHE_EXPIRY_SECONDS

# --- NEW CACHE PREFIXES FOR INTERMEDIATE DATA ---
SCREENSHOT_CACHE_PREFIX = "screenshot:"
TEXT_CONTENT_CACHE_PREFIX = "text_content:"


SCREENSHOT_CACHE_EXPIRY_SECONDS = WHOIS_CACHE_EXPIRY_SECONDS
TEXT_CONTENT_CACHE_EXPIRY_SECONDS = WHOIS_CACHE_EXPIRY_SECONDS



original_domain_whois_data: Optional[Dict[str, Any]] = None

def initialize_original_domain_whois(whois_obj: Whois, original_domain: str):
    global original_domain_whois_data
    if original_domain_whois_data is None:
        logging.info(f"Fetching WHOIS for original domain: {original_domain}")
        original_domain_whois_data = cached_whois_lookup(original_domain, whois_obj)
        if not is_valid_whois_response(original_domain_whois_data):
            logging.error(f"Failed to retrieve valid WHOIS data for original domain: {original_domain}")
            original_domain_whois_data = None # Reset if invalid



def is_defensive_registration(fuzzed_whois: Dict[str, Any], original_domain_name: str) -> bool:
    """
    Determines if a fuzzed domain is likely a defensive registration by the original brand.
    Compares registrant organization, name, email, and name servers using fuzzy matching.

    Args:
        fuzzed_whois: The WHOIS data dictionary for the fuzzed domain.
        original_whois: The WHOIS data dictionary for the original, legitimate domain.
        original_domain_name: The actual string name of the original domain (e.g., "google.com").

    Returns:
        True if it's likely a defensive registration, False otherwise.
    """
    if not fuzzed_whois or not original_domain_whois_data:
        logging.debug("Skipping defensive registration check: Missing WHOIS data for fuzzed or original domain.")
        return False

    # Helper function to safely get and clean string values
    def get_clean_value(data: Dict[str, Any], key: str) -> Optional[str]:
        value = data.get(key)
        if value is None:
            return None
        # Handle cases where get might return a list (e.g., domain_status)
        if isinstance(value, list) and value:
            # Join list items into a single string for comparison if appropriate
            # For registrant fields, a list is usually unexpected, but defensively handle.
            return ' '.join(str(v) for v in value).lower().strip()
        elif isinstance(value, str):
            return value.lower().strip()
        return None # Return None for unexpected types

    # 1. Compare Registrant Organization (most reliable)
    original_org = get_clean_value(original_domain_whois_data, 'registrant_organization')
    fuzzed_org = get_clean_value(fuzzed_whois, 'registrant_organization')

    if original_org and fuzzed_org: # Ensure both are non-None and non-empty strings
        org_similarity_score = fuzz.token_set_ratio(original_org, fuzzed_org)
        if org_similarity_score > 90: # Threshold for similarity (adjust as needed)
            logging.debug(f"Defensive match (Org): '{original_org}' vs '{fuzzed_org}' - Score {org_similarity_score}")
            return True

    # 2. Compare Registrant Name (less reliable, often generic like "Domain Administrator")
    original_name = get_clean_value(original_domain_whois_data, 'registrant_name')
    fuzzed_name = get_clean_value(fuzzed_whois, 'registrant_name')

    generic_names = {"domain administrator", "privacy protected", "private registration", "whoisguard"}
    # Only proceed if both names are not generic, or if one is specific and matches another
    if original_name in generic_names and fuzzed_name in generic_names:
        logging.debug(f"Skipping name match: Both names are generic ('{original_name}', '{fuzzed_name}').")
        pass # Do not return True based on generic names
    elif original_name and fuzzed_name: # Ensure both are non-None and non-empty strings
        name_similarity_score = fuzz.token_sort_ratio(original_name, fuzzed_name)
        if name_similarity_score > 90: # Higher threshold for names as they are usually more precise
            logging.debug(f"Defensive match (Name): '{original_name}' vs '{fuzzed_name}' - Score {name_similarity_score}")
            return True


    # 3. Compare Registrant Email (very strong indicator)
    original_email = get_clean_value(original_domain_whois_data, 'registrant_email')
    fuzzed_email = get_clean_value(fuzzed_whois, 'registrant_email')

    if original_email and fuzzed_email: # Ensure both are non-None and non-empty strings
        # Exact match is best for emails
        if original_email == fuzzed_email:
            logging.debug(f"Defensive match (Email exact): '{original_email}'")
            return True

        # Check domain part of the email
        original_email_domain_part = original_email.split('@')[-1] if '@' in original_email else ''
        fuzzed_email_domain_part = fuzzed_email.split('@')[-1] if '@' in fuzzed_email else ''

        if original_email_domain_part and fuzzed_email_domain_part: # Ensure both domain parts are non-empty
            email_domain_similarity_score = fuzz.partial_ratio(original_email_domain_part, fuzzed_email_domain_part)
            if email_domain_similarity_score > 90: # High threshold for email domain parts
                logging.debug(f"Defensive match (Email domain part): '{original_email_domain_part}' vs '{fuzzed_email_domain_part}' - Score {email_domain_similarity_score}")
                return True
            # Additional check: if original_domain_name is contained within the fuzzed email domain part
            if original_domain_name and original_domain_name in fuzzed_email_domain_part:
                logging.debug(f"Defensive match (Email domain contains original domain): '{fuzzed_email_domain_part}' contains '{original_domain_name}'")
                return True

    # 4. Compare Name Servers (extremely strong indicator)
    # Ensure name_servers exist and are iterable (list) before creating sets
    original_ns_raw = original_domain_whois_data.get('name_servers', [])
    fuzzed_ns_raw = fuzzed_whois.get('name_servers', [])

    original_ns_set = set(str(ns).lower().strip() for ns in original_ns_raw if ns is not None)
    fuzzed_ns_set = set(str(ns).lower().strip() for ns in fuzzed_ns_raw if ns is not None)


    if original_ns_set and fuzzed_ns_set: # Ensure both sets are non-empty
        # Check for direct overlap
        if not original_ns_set.isdisjoint(fuzzed_ns_set):
            logging.debug(f"Defensive match (Name Servers): Direct overlap found. Original: {original_ns_set}, Fuzzed: {fuzzed_ns_set}")
            return True

        # Check if fuzzed name servers contain the original domain name (e.g., ns1.google.com for google.com)
        for fns in fuzzed_ns_set:
            if original_domain_name and original_domain_name in fns:
                logging.debug(f"Defensive match (Name Servers): Fuzzed NS '{fns}' contains original domain '{original_domain_name}'")
                return True
            # Also check if the TLD of the original domain (e.g., .com) is part of the fuzzed NS,
            # and the main part of the domain matches.
            # This is a heuristic that might need fine-tuning.
            if original_domain_name:
                original_parts = original_domain_name.split('.')
                if len(original_parts) >= 2:
                    original_main_domain_part = original_parts[-2].lower() # e.g., 'google' from 'google.com'
                    original_tld_part = original_parts[-1].lower() # e.g., 'com'

                    if original_main_domain_part and original_main_domain_part in fns:
                        # Further refine: check if the fuzzed NS looks like a legitimate NS for the brand
                        # e.g., ns.brand.co.uk vs brand.com
                        # This is getting complex, a simpler check might be just for main domain part containment
                        logging.debug(f"Defensive match (Name Servers): Fuzzed NS '{fns}' contains original main domain part '{original_main_domain_part}'")
                        return True


    logging.debug(f"No defensive registration criteria met for this domain.")
    return False

# Example integration into your process_whois or subsequent processing
def process_domains_for_ownership(domains_with_whois: List[Dict[str, Any]], original_domain_name: str) -> List[Dict[str, Any]]:
    results_with_ownership = []
    for domain_info in domains_with_whois:
        fuzzed_whois = domain_info.get("whois")
        if fuzzed_whois:
            if is_defensive_registration(fuzzed_whois, original_domain_name):
                domain_info['ownership_status'] = 'Owned by Original Brand'
                domain_info['phishing_score'] = "N/A" # Clear the score if owned
            else:
                domain_info['ownership_status'] = 'Potentially Malicious'
                # Calculate phishing score later for these
        results_with_ownership.append(domain_info)
    return results_with_ownership


# --- Fuzzer and WHOIS functions (mostly unchanged, but ensure Redis client check) ---
def perform_fuzzing(domain: str, fuzzers: Optional[List[str]] = None,
                    dictionary: Optional[str] = None, tld: Optional[str] = None):
    fuzz = Fuzzer(domain, dictionary=dictionary, tld_dictionary=tld)
    fuzz.generate(fuzzers=fuzzers)
    return fuzz.domains


def cached_whois_lookup(domain_name: str, whois: Whois):
    """
    Fetch WHOIS data for a domain.
    Check Redis cache first; if not present, perform live WHOIS lookup, throttle, and store in Redis.
    """
    try:
        if redis_client:  # Check if redis_client is available
            cached_data = redis_client.get(domain_name)
            if cached_data:
                logging.debug(f"Cache hit for WHOIS {domain_name}")
                return convert_strings_to_dates(json.loads(cached_data))
        else:
            logging.debug(f"Redis client not available for WHOIS lookup of {domain_name}")

        logging.debug(f"Cache miss for WHOIS {domain_name} or Redis unavailable, fetching live WHOIS")
        time.sleep(THROTTLE_DELAY_SECONDS)
        whois_reply = whois.whois(domain_name)

        if whois_reply:
            whois_reply.pop('text', None)
            # Convert datetime objects to ISO strings for JSON serialization
            whois_reply_serializable = convert_dates_to_strings(whois_reply)

            logging.debug(f"WHOIS data fetched for {domain_name}")
            if redis_client:  # Check if redis_client is available for storing
                logging.debug(f"Storing WHOIS data in cache for {domain_name}")
                redis_client.setex(domain_name, WHOIS_CACHE_EXPIRY_SECONDS, json.dumps(whois_reply_serializable))
            # Return the version with datetime objects for immediate use
            return whois_reply
        return None
    except Exception as e:
        logging.error(f"Error fetching WHOIS for {domain_name}: {e}")
        return None

def is_valid_whois_response(whois_data: dict) -> bool:
    if not whois_data:
        return False

    # Only critical fields for considering WHOIS as valid
    required_fields = ['domain_name', 'creation_date', 'registrar']

    for field in required_fields:
        if field not in whois_data or not whois_data[field]:
            return False

    return True


def process_whois(domains: List[dict], original_domain: Optional[str] = None):
    whois = Whois()
    initialize_original_domain_whois(whois, original_domain)
    grouped_domains = defaultdict(list)
    for domain in domains:
        _, _, tld_val = domain_tld(domain["domain"])  # Renamed tld to tld_val to avoid conflict
        whois_server = Whois.WHOIS_TLD.get(tld_val, Whois.WHOIS_IANA)
        if whois_server:
            grouped_domains[whois_server].append(domain)
        else:
            logging.warning(f"No WHOIS server found for TLD: {tld_val}")

    def fetch_whois_data(domain_dict: dict):  # Renamed domain to domain_dict
        try:
            whois_reply = cached_whois_lookup(domain_dict["domain"], whois)
            if is_valid_whois_response(whois_reply):
                domain_dict["whois"] = whois_reply
            else:
                logging.warning(f"WHOIS data for {domain_dict['domain']} is incomplete or invalid.")
                domain_dict["whois"] = None
        except Exception as e:
            logging.error(f"Error processing WHOIS for domain {domain_dict['domain']}: {e}")
            domain_dict["whois"] = None
        return domain_dict

    all_results = []

    def process_whois_group(domains_group: List[dict]):
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=10) as executor:  # Consider making max_workers configurable
            futures = [executor.submit(fetch_whois_data, domain_item) for domain_item in
                       domains_group]  # Renamed domain to domain_item
            return [future.result() for future in concurrent.futures.as_completed(futures)]

    with concurrent.futures.ThreadPoolExecutor() as main_executor:
        server_futures = [
            main_executor.submit(process_whois_group, domains_group)
            for domains_group in grouped_domains.values()
        ]
        for future in concurrent.futures.as_completed(server_futures):
            all_results.extend(future.result())
    return process_domains_for_ownership([domain_item for domain_item in all_results if
            domain_item.get("whois") is not None], original_domain)  # Renamed domain to domain_item


def geoip_lookup(domain: str):
    return {"country": "US", "city": "New York", "latitude": 40.7128, "longitude": -74.0060}


def get_url_with_scheme_fallback(domain: str, timeout: int = 10) -> Optional[requests.Response]:
    urls_to_try = [f"https://{domain}", f"http://{domain}"]
    last_exception = None
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    for url_attempt in urls_to_try:
        try:
            response = requests.get(url_attempt, timeout=timeout, allow_redirects=True, headers=headers, verify=True)
            response.raise_for_status()
            logging.info(f"Successfully fetched {response.url} (original request: {url_attempt})")
            return response
        except requests.exceptions.SSLError as e:
            logging.debug(f"SSL Error for {url_attempt}: {e}. Trying next scheme if available.")
            last_exception = e
        except requests.exceptions.ConnectionError as e:
            logging.debug(f"Connection Error for {url_attempt}: {e}. Trying next scheme if available.")
            last_exception = e
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request failed for {url_attempt}: {e}")
            last_exception = e
        if url_attempt.startswith("https://"):
            logging.debug(f"HTTPS attempt failed for {domain}. Falling back to HTTP.")
    logging.warning(
        f"Failed to fetch content for domain '{domain}' after trying all schemes. Last error: {last_exception}")
    return None


def render_screenshot_with_fallback(browser: HeadlessBrowser, domain: str) -> Tuple[Optional[np.ndarray], Optional[str]]:
    """
    Renders a screenshot of the domain, trying HTTPS then HTTP.
    Uses Redis for caching screenshots. Returns a grayscale NumPy array and base64 string.
    """
    cache_key = f"{SCREENSHOT_CACHE_PREFIX}{domain}"

    if redis_client:
        try:
            cached_screenshot_data = redis_client.get(cache_key)
            if cached_screenshot_data:
                logging.info(f"Cache hit for screenshot: {domain}")
                # Cached data is a JSON string containing base64 for gray and color images
                cached_dict = json.loads(cached_screenshot_data.decode('utf-8'))
                gray_b64 = cached_dict.get("gray_b64")
                color_b64 = cached_dict.get("color_b64")

                if gray_b64 and color_b64:
                    gray_bytes = base64.b64decode(gray_b64)
                    color_bytes = base64.b64decode(color_b64)
                    gray_image = cv2.imdecode(np.frombuffer(gray_bytes, np.uint8), cv2.IMREAD_GRAYSCALE)
                    # The color_image base64 is already what we need for the output dict
                    return gray_image, color_b64
                else:
                    logging.warning(f"Cached screenshot data for {domain} incomplete. Re-rendering.")
        except Exception as e_cache:
            logging.warning(f"Error reading screenshot from cache for {domain}: {e_cache}. Re-rendering.")

    logging.info(f"Rendering screenshot for: {domain} (active rendering)")
    urls_to_try = [f"https://{domain}", f"http://{domain}"]
    last_exception = None

    for url_attempt in urls_to_try:
        try:
            browser.new_tab(url_attempt)
            time.sleep(BROWSER_ACTION_DELAY)

            gray_image_np, screenshot_base64_colored = browser.get_screenshot_as_png()
            if gray_image_np is None:
                raise ValueError("Screenshot attempt failed or timed out.")

            browser.close_current_tab_and_switch(0)

            if redis_client:
                try:
                    _, gray_buffer = cv2.imencode('.png', gray_image_np)
                    gray_base64_str = base64.b64encode(gray_buffer).decode('utf-8')  # Corrected line

                    cache_value = json.dumps({
                        "gray_b64": gray_base64_str,
                        "color_b64": screenshot_base64_colored
                    })
                    redis_client.setex(cache_key, SCREENSHOT_CACHE_EXPIRY_SECONDS, cache_value)
                    logging.info(f"Screenshot cached for: {domain}")
                except Exception as e_cache_write:
                    logging.warning(f"Error writing screenshot to cache for {domain}: {e_cache_write}")

            return gray_image_np, screenshot_base64_colored

        except Exception as e:
            logging.warning(f"Screenshot attempt failed for {url_attempt}: {e}")
            last_exception = e
            try:  # Best effort to clean up tab
                browser.close_current_tab_and_switch(0)
            except Exception as e_close:
                logging.debug(f"Error closing tab during screenshot failure cleanup for {url_attempt}: {e_close}")

    logging.error(
        f"Failed to render screenshot for domain '{domain}' after trying all schemes. Last error: {last_exception}")
    return None , None


# --- MODIFIED: fetch_text_content (WITH REDIS CACHING) ---
def fetch_text_content(domain: str, timeout: int = 10) -> str:
    """
    Fetches and extracts text content (title, headings, paragraphs) from a domain.
    Uses Redis for caching text content. Tries HTTPS then HTTP.
    """
    cache_key = f"{TEXT_CONTENT_CACHE_PREFIX}{domain}"

    if redis_client:
        try:
            cached_text_data = redis_client.get(cache_key)
            if cached_text_data:
                logging.info(f"Cache hit for text content: {domain}")
                return cached_text_data.decode('utf-8')
        except Exception as e_cache:
            logging.warning(f"Error reading text content from cache for {domain}: {e_cache}. Re-fetching.")

    logging.info(f"Fetching text for: {domain} (active fetching)")
    response = get_url_with_scheme_fallback(domain, timeout=timeout)
    if not response:
        return ""

    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        headings_text_list = [h.get_text(separator=' ', strip=True) for h in soup.find_all(['h1', 'h2', 'h3'])]
        paragraphs_text_list = [p.get_text(separator=' ', strip=True) for p in soup.find_all('p')]
        full_text_parts = [title] + \
                          [t for t in headings_text_list if t] + \
                          [t for t in paragraphs_text_list if t]
        full_text = " ".join(filter(None, full_text_parts)).strip()

        if redis_client and full_text: # Only cache if text was successfully extracted
            try:
                redis_client.setex(cache_key, TEXT_CONTENT_CACHE_EXPIRY_SECONDS, full_text.encode('utf-8'))
                logging.info(f"Text content cached for: {domain}")
            except Exception as e_cache_write:
                logging.warning(f"Error writing text content to cache for {domain}: {e_cache_write}")

        return full_text
    except Exception as e:
        final_url_attempted = response.url if response else "N/A"
        logging.warning(f"Error parsing HTML content for {domain} (final URL: {final_url_attempted}): {e}")
        return ""


# --- Comparison functions (unchanged) ---
def compare_text_content(text1: str, text2: str) -> float:
    if not text1 or not text2: return 0.0
    if text1.isspace() and text2.isspace(): return 1.0
    if text1.isspace() or text2.isspace(): return 0.0
    try:
        vectorizer = TfidfVectorizer().fit([text1, text2])
        vectors = vectorizer.transform([text1, text2])
        if vectors.shape[0] < 2 or vectors.nnz == 0: return 0.0
        similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
        return float(similarity)
    except Exception as e:
        logging.error(f"Error comparing text content: {e}", exc_info=True)
        return 0.0


def compare_screenshot_similarity(img1_np: Optional[np.ndarray], img2_np: Optional[np.ndarray]) -> float:
    if img1_np is None or img2_np is None or img1_np.size == 0 or img2_np.size == 0: return 0.0
    try:
        img2_np_resized = img2_np
        if img1_np.shape != img2_np.shape:
            logging.debug(
                f"Resizing screenshot for SSIM. Original img2: {img2_np.shape}, Target (img1): {img1_np.shape}")
            pil_img2 = Image.fromarray(img2_np)
            pil_img2_resized = pil_img2.resize((img1_np.shape[1], img1_np.shape[0]), Image.Resampling.LANCZOS)
            img2_np_resized = np.array(pil_img2_resized)

        min_dim_img1 = min(img1_np.shape[0], img1_np.shape[1])
        current_win_size = min(7, min_dim_img1)
        if current_win_size < 3:
            logging.warning(f"One or both images too small (min_dim < 3) for reliable SSIM. Shape1: {img1_np.shape}")
            return 0.0
        if current_win_size % 2 == 0: current_win_size -= 1
        if current_win_size < 3:
            logging.warning(f"Adjusted win_size {current_win_size} is too small for SSIM.")
            return 0.0
        data_range = 255.0
        score, _ = ssim(img1_np, img2_np_resized, full=True, data_range=data_range, win_size=current_win_size)
        return float(score)
    except Exception as e:
        logging.error(f"Error comparing screenshots: {e}", exc_info=True)
        return 0.0


def calculate_phishing_score(is_defensive: bool, text_score: float, image_score: float) -> float:
    if is_defensive:
        # If it's a defensive registration, the score should be very low or zero,
        # regardless of content similarity.
        return 0.0 # Or a minimal non-zero score like 0.05

    clamped_text_score = max(0.0, min(text_score, 1.0))
    clamped_image_score = max(0.0, min(image_score, 1.0))

    # If not defensive, calculate based on similarities
    # You might remove the `whois_exists` part here if `is_defensive` already covers that
    # score = 0.1 if whois_exists else 0.0 # Remove this if you rely purely on defensive check for WHOIS
    score = 0.45 * clamped_text_score
    score += 0.45 * clamped_image_score

    return min(max(score, 0.0), 1.0)


def numpy_to_base64(img_np: Optional[np.ndarray]) -> Optional[str]:
    if img_np is None: return None
    try:
        img_np_uint8 = img_np.astype(np.uint8) if img_np.dtype != np.uint8 else img_np
        img_pil = Image.fromarray(img_np_uint8)
        buffer = BytesIO()
        img_pil.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    except Exception as e:
        logging.error(f"Error converting numpy array to base64: {e}", exc_info=True)
        return None

# --- process_domain_for_worker (updated to call caching functions) ---
def process_domain_for_worker(browser_instance: HeadlessBrowser,
                              domain_data_dict: Dict[str, Any],
                              original_ref_image_np: Optional[np.ndarray],
                              colored_original_image: str,
                              original_ref_text: str,
                              original_domain_name: str,
                              original_domain_whois_data: Optional[Dict[str, Any]] # Added this back
                              ) -> Dict[str, Any]:
    fuzzed_domain_name = domain_data_dict.get("domain")
    domain_data_dict.update({
        "screenshot_base64": None, "text_similarity": 0.0, "image_similarity": 0.0,
        "phishing_score": 0.0, "status": "unprocessed_in_worker", "error_message": None,
        "ownership_status": "Unknown" # Initialize ownership status
    })
    if not fuzzed_domain_name:
        logging.warning(f"Worker: Missing 'domain' key in domain_data: {domain_data_dict}")
        domain_data_dict.update({"status": "error", "error_message": "Missing domain name"})
        return domain_data_dict

    logging.info(f"Worker: Actively processing domain: {fuzzed_domain_name} with browser {id(browser_instance)}")
    try:
        # These calls now *internally* handle their own caching
        fuzzed_image_np, colored_image = render_screenshot_with_fallback(browser_instance, fuzzed_domain_name)
        fuzzed_text_content = fetch_text_content(fuzzed_domain_name)

        text_similarity_score = compare_text_content(original_ref_text,
                                                     fuzzed_text_content) if original_ref_text else 0.0
        image_similarity_score = compare_screenshot_similarity(original_ref_image_np,
                                                               fuzzed_image_np) if original_ref_image_np is not None else 0.0

        is_defensive_reg = False
        fuzzed_whois_data = domain_data_dict.get("whois") # Get WHOIS from the input data

        if original_domain_whois_data and fuzzed_whois_data: # Ensure both are available for comparison
            is_defensive_reg = is_defensive_registration(fuzzed_whois_data, original_domain_name)
            if is_defensive_reg:
                domain_data_dict["ownership_status"] = "Owned by Original Brand"
            else:
                domain_data_dict["ownership_status"] = "Potentially Malicious"
        else:
            domain_data_dict["ownership_status"] = "WHOIS Data Missing" # Indicate if WHOIS is missing for checks

        phishing_score_val = calculate_phishing_score(
            is_defensive_reg, text_similarity_score, image_similarity_score
        )

        domain_data_dict.update({
            "screenshot_base64": colored_image,
            "text_similarity": float(text_similarity_score),
            "image_similarity": float(image_similarity_score),
            "phishing_score": float(phishing_score_val),
            "status": "processed_in_worker"
        })

        if is_defensive_reg:
            domain_data_dict["status"] = "defensive_registration"
            domain_data_dict["phishing_score"] = 0.0
            domain_data_dict["text_similarity"] = "N/A (Defensive)" # Indicate why it's N/A
            domain_data_dict["image_similarity"] = "N/A (Defensive)"


    except Exception as e:
        logging.error(f"Worker: Critical error processing domain {fuzzed_domain_name}: {e}", exc_info=True)
        domain_data_dict.update({
            "status": "error_in_worker", "error_message": str(e)
        })
    return domain_data_dict


def evaluate_phishing_risk(original_domain: str, domains_to_check: List[Dict[str, Any]],
                           disable_javascript_Browse: bool = False,
                           browser_page_load_strategy: str = 'eager',
                           BROWSER_ACTION_DELAY: float = 1.0 # Default delay
                           ) -> List[Dict[str, Any]]:

    if not logging.getLogger().hasHandlers():
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

    current_max_workers = 10  # Use configured max workers
    total_domains_to_check_count = len(domains_to_check)
    processed_domain_count = 0

    logging.info(
        f"Starting phishing risk evaluation. Original: '{original_domain}'. "
        f"Total domains to evaluate: {total_domains_to_check_count} using up to {current_max_workers} worker threads."
    )

    all_results: List[Dict[str, Any]] = []
    domains_for_active_processing: List[Dict[str, Any]] = []

    # --- Phase 1: Capture original domain data ---
    original_browser_instance: Optional[HeadlessBrowser] = None
    original_ref_image_np: Optional[np.ndarray] = None
    colored_original_image: str = ""
    original_ref_text: str = ""
    critical_original_failure = False

    try:
        # Cache check for original domain's data (screenshot and text)
        logging.info(f"Checking cache for original domain data: {original_domain}")
        original_screenshot_cache_key = f"{SCREENSHOT_CACHE_PREFIX}{original_domain}"
        original_text_cache_key = f"{TEXT_CONTENT_CACHE_PREFIX}{original_domain}"

        cached_original_screenshot = None
        cached_original_text = None

        if redis_client:
            try:
                cached_original_screenshot_data = redis_client.get(original_screenshot_cache_key)
                if cached_original_screenshot_data:
                    logging.info(f"Cache hit for original screenshot: {original_domain}")
                    cached_dict = json.loads(cached_original_screenshot_data.decode('utf-8'))
                    gray_b64 = cached_dict.get("gray_b64")
                    color_b64 = cached_dict.get("color_b64")
                    if gray_b64 and color_b64:
                        gray_bytes = base64.b64decode(gray_b64)
                        original_ref_image_np = cv2.imdecode(np.frombuffer(gray_bytes, np.uint8), cv2.IMREAD_GRAYSCALE)
                        colored_original_image = color_b64
            except Exception as e_cache_read:
                logging.warning(f"Error reading original screenshot from cache for {original_domain}: {e_cache_read}")

            try:
                cached_original_text_data = redis_client.get(original_text_cache_key)
                if cached_original_text_data:
                    logging.info(f"Cache hit for original text content: {original_domain}")
                    original_ref_text = cached_original_text_data.decode('utf-8')
            except Exception as e_cache_read:
                logging.warning(f"Error reading original text from cache for {original_domain}: {e_cache_read}")

        # If original data is not fully cached, fetch it
        if original_ref_image_np is None or not original_ref_text:
            logging.info(f"Initializing browser for original domain: {original_domain} (for missing data)")
            original_browser_instance = HeadlessBrowser(
                disable_javascript=disable_javascript_Browse,
                page_load_strategy=browser_page_load_strategy
            )
            logging.info(f"Capturing baseline data for original domain: {original_domain} (active fetch)")

            if original_ref_image_np is None:
                logging.info(f"Fetching original screenshot for {original_domain}")
                original_ref_image_np_fetched, colored_original_image_fetched = render_screenshot_with_fallback(
                    original_browser_instance, original_domain)
                if original_ref_image_np_fetched is not None:
                    original_ref_image_np = original_ref_image_np_fetched
                    colored_original_image = colored_original_image_fetched
                else:
                    logging.error(f"Failed to fetch original screenshot for {original_domain}.")

            if not original_ref_text:
                logging.info(f"Fetching original text content for {original_domain}")
                original_ref_text = fetch_text_content(original_domain)  # This uses requests, not the browser instance

            if original_ref_image_np is None and not original_ref_text:
                logging.critical("CRITICAL: Both screenshot and text fetch failed for the original domain.")
                critical_original_failure = True
            elif original_ref_image_np is None:
                logging.error(f"CRITICAL: Screenshot capture failed for original domain '{original_domain}'.")
            elif not original_ref_text:
                logging.warning(f"Original domain '{original_domain}' text content failed/empty.")


    except Exception as e_orig:
        logging.critical(
            f"Failed to initialize browser or capture data for original domain '{original_domain}': {e_orig}",
            exc_info=True)
        critical_original_failure = True
    finally:
        if original_browser_instance:
            original_browser_instance.stop()
            logging.info(f"Original domain browser for {original_domain} stopped.")

    # --- Phase 2: Check cache for final results of fuzzed domains ---
    if redis_client:
        logging.info(f"Checking FINAL RESULT cache for {total_domains_to_check_count} fuzzed domains...")
        for domain_dict_item in domains_to_check:
            domain_name = domain_dict_item.get("domain")
            if not domain_name:
                logging.warning(f"Skipping item with no domain name for cache check: {domain_dict_item}")
                error_item = {
                    **domain_dict_item,
                    "status": "error_no_domain_name_for_cache",
                    "error_message": "Domain name missing, cannot check cache or process.",
                    "phishing_score": 0.0, "text_similarity": 0.0, "image_similarity": 0.0,
                    "screenshot_base64": None
                }
                all_results.append(error_item)
                processed_domain_count += 1
                continue

            cache_key = f"{FINAL_RESULT_CACHE_PREFIX}{domain_name}"
            try:
                cached_data_json = redis_client.get(cache_key)
                if cached_data_json:
                    logging.info(f"Cache hit for FINAL RESULT for domain: {domain_name} ")
                    cached_data = json.loads(cached_data_json.decode('utf-8'))
                    if "whois" in cached_data and cached_data["whois"] is not None:
                        cached_data["whois"] = convert_strings_to_dates(cached_data["whois"])

                    logging.info(f"Cache hit for final result: {domain_name}")
                    all_results.append(cached_data)
                    processed_domain_count += 1
                else:
                    domains_for_active_processing.append(domain_dict_item)
            except Exception as e_cache:
                logging.warning(f"Redis cache read or JSON parse error for {cache_key}: {e_cache}. Will re-process.")
                domains_for_active_processing.append(domain_dict_item)
        logging.info(f"Cache check complete. Found {len(all_results)} results in cache. "
                     f"{len(domains_for_active_processing)} domains require active processing.")
    else:
        logging.info("Redis client not available. All domains will be processed actively.")
        domains_for_active_processing = list(domains_to_check)

    # --- Phase 3: Process domains not found in cache (with browser pooling) ---
    if domains_for_active_processing and not critical_original_failure:

        browser_pool_queue = concurrent.futures.ThreadPoolExecutor(max_workers=current_max_workers,
                                                                   thread_name_prefix="BrowserPoolInit")
        browser_instances: List[HeadlessBrowser] = []
        try:
            futures = [browser_pool_queue.submit(HeadlessBrowser,
                                                 disable_javascript=disable_javascript_Browse,
                                                 page_load_strategy=browser_page_load_strategy)
                       for _ in range(current_max_workers)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    browser_instances.append(future.result())
                except Exception as e_browser_init:
                    logging.critical(f"Failed to initialize a browser instance for the pool: {e_browser_init}")
                    for b in browser_instances: b.stop()
                    raise RuntimeError(f"Failed to initialize browser pool: {e_browser_init}") from e_browser_init
        finally:
            browser_pool_queue.shutdown(wait=True)

        if not browser_instances:
            logging.critical(
                "No browser instances successfully initialized in the pool. Cannot proceed with active processing.")
            for d_item in domains_for_active_processing:
                d_item.update(
                    {"status": "error_browser_pool_empty", "error_message": "Browser pool initialization failed."})
                all_results.append(d_item)
            return all_results

        browser_queue = queue.Queue()
        for browser in browser_instances:
            browser_queue.put(browser)

        def worker_task_with_browser_pool(domain_dict_item: Dict[str, Any],
                                          orig_img_np: Optional[np.ndarray],
                                          colored_original_image_str: str,
                                          orig_txt: str,
                                          original_domain_str: str,
                                          original_whois_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
            browser_instance_for_task = None
            try:
                browser_instance_for_task = browser_queue.get(timeout=60)
                logging.debug(f"Worker thread {threading.get_ident()} acquired browser {id(browser_instance_for_task)}")
                if not browser_instance_for_task.is_alive():
                    logging.warning(
                        f"Acquired browser {id(browser_instance_for_task)} was not alive. Attempting re-initialization.")
                    try:
                        browser_instance_for_task.stop()
                        browser_instance_for_task = HeadlessBrowser(
                            disable_javascript=disable_javascript_Browse,
                            page_load_strategy=browser_page_load_strategy
                        )
                        logging.info(f"Re-initialized browser {id(browser_instance_for_task)} successfully.")
                    except Exception as e_reinit:
                        logging.error(f"Failed to re-initialize browser for worker: {e_reinit}")
                        raise RuntimeError(f"Browser re-initialization failed: {e_reinit}")

                result = process_domain_for_worker(browser_instance_for_task,
                                                   domain_dict_item,
                                                   orig_img_np,
                                                   colored_original_image_str,
                                                   orig_txt,
                                                   original_domain_str,
                                                   original_whois_data)
                return result
            except queue.Empty:
                logging.error("Worker: Timed out waiting for an available browser instance from the pool.")
                domain_dict_item.update({
                    "status": "error_no_browser_available",
                    "error_message": "No browser instance available from pool",
                    "phishing_score": 0.0, "text_similarity": 0.0, "image_similarity": 0.0, "screenshot_base64": None
                })
                return domain_dict_item
            except Exception as e:
                logging.error(f"Worker: Error during browser task for {domain_dict_item.get('domain')}: {e}",
                              exc_info=True)
                domain_dict_item.update({
                    "status": "error_browser_task",
                    "error_message": str(e),
                    "phishing_score": 0.0, "text_similarity": 0.0, "image_similarity": 0.0, "screenshot_base64": None
                })
                return domain_dict_item
            finally:
                if browser_instance_for_task:
                    browser_queue.put(browser_instance_for_task)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=current_max_workers,
                                                       thread_name_prefix="PhishEvalWorker") as executor:
                future_to_domain_map = {
                    executor.submit(worker_task_with_browser_pool, domain_item,
                                    original_ref_image_np, colored_original_image, original_ref_text,
                                    original_domain, original_domain_whois_data): domain_item
                    for domain_item in domains_for_active_processing
                }

                for future_task in concurrent.futures.as_completed(future_to_domain_map):
                    original_input_domain_dict = future_to_domain_map[future_task]
                    domain_name_for_log = original_input_domain_dict.get('domain', 'unknown_domain')
                    try:
                        processed_domain_data = future_task.result()
                        if critical_original_failure:
                            processed_domain_data["phishing_score"] = 0.0
                            current_error = processed_domain_data.get("error_message", "")
                            processed_domain_data[
                                "error_message"] = f"{current_error}; Original domain capture failed".lstrip("; ")
                            processed_domain_data["status"] = "error_original_failed"

                        if redis_client:
                            domain_to_cache_name = processed_domain_data.get("domain")
                            if domain_to_cache_name:
                                cache_key_store = f"{FINAL_RESULT_CACHE_PREFIX}{domain_to_cache_name}"
                                try:
                                    data_to_cache = processed_domain_data.copy()
                                    if "whois" in data_to_cache and data_to_cache["whois"] is not None:
                                        data_to_cache["whois"] = convert_dates_to_strings(data_to_cache["whois"])
                                    redis_client.setex(cache_key_store, FINAL_RESULT_CACHE_EXPIRY_SECONDS,
                                                       json.dumps(data_to_cache))
                                    logging.info(f"Stored final result in cache for: {domain_to_cache_name}")
                                except Exception as e_cache_write:
                                    logging.warning(
                                        f"Redis cache write error for final result {domain_to_cache_name}: {e_cache_write}")

                        all_results.append(processed_domain_data)
                    except Exception as task_exc:
                        logging.error(
                            f"MainThread: Unhandled exception from worker task for domain '{domain_name_for_log}': {task_exc}",
                            exc_info=True)
                        original_input_domain_dict.update({
                            "status": "error_future_exception",
                            "error_message": f"Future task exception: {str(task_exc)}",
                            "phishing_score": 0.0, "text_similarity": 0.0, "image_similarity": 0.0,
                            "screenshot_base64": None
                        })
                        all_results.append(original_input_domain_dict)
                    finally:
                        processed_domain_count += 1
                        remaining_count = total_domains_to_check_count - processed_domain_count
                        logging.info(f"------------------------------------------------")
                        logging.info(
                            f"Domain '{domain_name_for_log}' processing reported. Overall Progress: {processed_domain_count}/{total_domains_to_check_count}. Remaining: {remaining_count}")
        except Exception as global_pool_exc:
            logging.critical(f"Critical error during threaded processing: {global_pool_exc}", exc_info=True)
            processed_domain_names_in_results = {pr.get("domain") for pr in all_results}
            for d_item in domains_for_active_processing:
                if d_item.get("domain") not in processed_domain_names_in_results:
                    d_item.update({
                        "status": "error_pool_level", "error_message": f"Pool execution error: {str(global_pool_exc)}",
                        "phishing_score": 0.0, "text_similarity": 0.0, "image_similarity": 0.0,
                        "screenshot_base64": None
                    })
                    all_results.append(d_item)
                    processed_domain_count += 1
                    logging.info(
                        f"Marking domain {d_item.get('domain')} with pool error. Overall Progress: {processed_domain_count}/{total_domains_to_check_count}.")
        finally:
            logging.info("Stopping all browser instances in the pool...")
            for browser in browser_instances:
                if browser.is_alive():
                    browser.stop()
            logging.info("All browser instances stopped.")

    all_results.sort(key=lambda x: x.get("phishing_score", 0.0), reverse=True)
    logging.info(
        f"Phishing risk evaluation completed. Generated {len(all_results)} results for original '{original_domain}'.")
    return all_results


