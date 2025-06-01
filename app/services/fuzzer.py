
import idna
from typing import Optional, List, Set, Generator, Tuple, Dict, Any
from app.config.dconfig import VALID_FQDN_REGEX
from app.services.permutation import Permutation
from app.utils.domain_util import domain_tld
import itertools

# --- Fuzzer Class ---

class Fuzzer:
    """
    Generates domain name permutations based on an input domain using various
    fuzzing techniques. These techniques include character manipulations
    (homoglyphs, typos, keyboard errors), structural changes (hyphenation,
    subdomain generation), and dictionary-based attacks.

    The fuzzer can apply these techniques to both the main domain part and
    the subdomain part of the input.
    """

    # --- Static Data ---
    # These dictionaries store character mappings, keyboard layouts, and lists
    # used by the various fuzzing algorithms.

    # glyphs_idn_by_tld: Maps Top-Level Domains (TLDs) to dictionaries of
    # characters and their allowed Internationalized Domain Name (IDN) homoglyphs.
    # This allows for TLD-specific character substitution rules.
    glyphs_idn_by_tld: Dict[str, Dict[str, Tuple[str, ...]]] = {
        **dict.fromkeys(
            ['ad', 'cz', 'sk', 'uk', 'co.uk', 'nl', 'edu', 'us', 'ai', 'io', 'jp', 'co.jp', 'ad.jp', 'ne.jp', 'cn',
             'com.cn', 'tw', 'com.tw', 'net.tw'], {}), # TLDs with no *extra* specified glyphs
        'info': {'a': ('á', 'ä', 'å', 'ą'), 'c': ('ć', 'č'), 'e': ('é', 'ė', 'ę'), 'i': ('í', 'į'), 'l': ('ł',),
                 'n': ('ñ', 'ń'), 'o': ('ó', 'ö', 'ø', 'ő'), 's': ('ś', 'š'), 'u': ('ú', 'ü', 'ū', 'ű', 'ų'),
                 'z': ('ź', 'ż', 'ž'), 'ae': ('æ',)},
        'br': {'a': ('à', 'á', 'â', 'ã'), 'c': ('ç',), 'e': ('é', 'ê'), 'i': ('í',), 'o': ('ó', 'ô', 'õ'),
               'u': ('ú', 'ü'), 'y': ('ý', 'ÿ')},
        'dk': {'a': ('ä', 'å'), 'e': ('é',), 'o': ('ö', 'ø'), 'u': ('ü',), 'ae': ('æ',)},
        'eu': {'a': ('á', 'à', 'ă', 'â', 'å', 'ä', 'ã', 'ą', 'ā'), 'c': ('ć', 'ĉ', 'č', 'ċ', 'ç'), 'd': ('ď', 'đ'),
               'e': ('é', 'è', 'ĕ', 'ê', 'ě', 'ë', 'ė', 'ę', 'ē'), 'g': ('ğ', 'ĝ', 'ġ', 'ģ'), 'h': ('ĥ', 'ħ'),
               'i': ('í', 'ì', 'ĭ', 'î', 'ï', 'ĩ', 'į', 'ī'), 'j': ('ĵ',), 'k': ('ķ', 'ĸ'), 'l': ('ĺ', 'ľ', 'ļ', 'ł'),
               'n': ('ń', 'ň', 'ñ', 'ņ'), 'o': ('ó', 'ò', 'ŏ', 'ô', 'ö', 'ő', 'õ', 'ø', 'ō'), 'r': ('ŕ', 'ř', 'ŗ'),
               's': ('ś', 'ŝ', 'š', 'ş'), 't': ('ť', 'ţ', 'ŧ'), 'u': ('ú', 'ù', 'ŭ', 'û', 'ů', 'ü', 'ű', 'ũ', 'ų', 'ū'),
               'w': ('ŵ',), 'y': ('ý', 'ŷ', 'ÿ'), 'z': ('ź', 'ž', 'ż'), 'ae': ('æ',), 'oe': ('œ',)},
        'fi': {'3': ('ʒ',), 'a': ('á', 'ä', 'å', 'â'), 'c': ('č',), 'd': ('đ',), 'g': ('ǧ', 'ǥ'), 'k': ('ǩ',),
               'n': ('ŋ',), 'o': ('õ', 'ö'), 's': ('š',), 't': ('ŧ',), 'z': ('ž',)},
        'no': {'a': ('á', 'à', 'ä', 'å'), 'c': ('č', 'ç'), 'e': ('é', 'è', 'ê'), 'i': ('ï',), 'n': ('ŋ', 'ń', 'ñ'),
               'o': ('ó', 'ò', 'ô', 'ö', 'ø'), 's': ('š',), 't': ('ŧ',), 'u': ('ü',), 'z': ('ž',), 'ae': ('æ',)},
        'be': {'a': ('à', 'á', 'â', 'ã', 'ä', 'å'), 'c': ('ç',), 'e': ('è', 'é', 'ê', 'ë'), 'i': ('ì', 'í', 'î', 'ï'),
               'n': ('ñ',), 'o': ('ò', 'ó', 'ô', 'õ', 'ö'), 'u': ('ù', 'ú', 'û', 'ü'), 'y': ('ý', 'ÿ'), 'ae': ('æ',),
               'oe': ('œ',)},
        'ca': {'a': ('à', 'â'), 'c': ('ç',), 'e': ('è', 'é', 'ê', 'ë'), 'i': ('î', 'ï'), 'o': ('ô',),
               'u': ('ù', 'û', 'ü'), 'y': ('ÿ',), 'ae': ('æ',), 'oe': ('œ',)},
    }
    # Apply shared rules for brevity and maintainability
    glyphs_idn_by_tld.update(dict.fromkeys(['de', 'pl'], glyphs_idn_by_tld['eu'])) # DE, PL share EU rules
    glyphs_idn_by_tld.update(dict.fromkeys(['fr', 're', 'yt', 'pm', 'wf', 'tf', 'ch', 'li'], glyphs_idn_by_tld['be'])) # FR, etc. share BE rules
    glyphs_idn_by_tld.update({'com.br': glyphs_idn_by_tld['br']}) # com.br shares BR rules

    # glyphs_unicode: General Unicode homoglyphs (visually similar characters)
    # These are applied broadly, in addition to TLD-specific ones.
    glyphs_unicode: Dict[str, Tuple[str, ...]] = {
        '2': ('ƻ',), '3': ('ʒ',), '5': ('ƽ',),
        'a': ('ạ', 'ă', 'ȧ', 'ɑ', 'å', 'ą', 'â', 'ǎ', 'á', 'ə', 'ä', 'ã', 'ā', 'à'), 'b': ('ḃ', 'ḅ', 'ƅ', 'ʙ', 'ḇ', 'ɓ'),
        'c': ('č', 'ᴄ', 'ċ', 'ç', 'ć', 'ĉ', 'ƈ'), 'd': ('ď', 'ḍ', 'ḋ', 'ɖ', 'ḏ', 'ɗ', 'ḓ', 'ḑ', 'đ'),
        'e': ('ê', 'ẹ', 'ę', 'è', 'ḛ', 'ě', 'ɇ', 'ė', 'ĕ', 'é', 'ë', 'ē', 'ȩ'), 'f': ('ḟ', 'ƒ'),
        'g': ('ǧ', 'ġ', 'ǵ', 'ğ', 'ɡ', 'ǥ', 'ĝ', 'ģ', 'ɢ'), 'h': ('ȟ', 'ḫ', 'ḩ', 'ḣ', 'ɦ', 'ḥ', 'ḧ', 'ħ', 'ẖ', 'ⱨ', 'ĥ'),
        'i': ('ɩ', 'ǐ', 'í', 'ɪ', 'ỉ', 'ȋ', 'ɨ', 'ï', 'ī', 'ĩ', 'ị', 'î', 'ı', 'ĭ', 'į', 'ì'), 'j': ('ǰ', 'ĵ', 'ʝ', 'ɉ'),
        'k': ('ĸ', 'ǩ', 'ⱪ', 'ḵ', 'ķ', 'ᴋ', 'ḳ'), 'l': ('ĺ', 'ł', 'ɫ', 'ļ', 'ľ'), 'm': ('ᴍ', 'ṁ', 'ḿ', 'ṃ', 'ɱ'),
        'n': ('ņ', 'ǹ', 'ń', 'ň', 'ṅ', 'ṉ', 'ṇ', 'ꞑ', 'ñ', 'ŋ'),
        'o': ('ö', 'ó', 'ȯ', 'ỏ', 'ô', 'ᴏ', 'ō', 'ò', 'ŏ', 'ơ', 'ő', 'õ', 'ọ', 'ø'), 'p': ('ṗ', 'ƿ', 'ƥ', 'ṕ'), 'q': ('ʠ',),
        'r': ('ʀ', 'ȓ', 'ɍ', 'ɾ', 'ř', 'ṛ', 'ɽ', 'ȑ', 'ṙ', 'ŗ', 'ŕ', 'ɼ', 'ṟ'),
        's': ('ṡ', 'ș', 'ŝ', 'ꜱ', 'ʂ', 'š', 'ś', 'ṣ', 'ş'), 't': ('ť', 'ƫ', 'ţ', 'ṭ', 'ṫ', 'ț', 'ŧ'),
        'u': ('ᴜ', 'ų', 'ŭ', 'ū', 'ű', 'ǔ', 'ȕ', 'ư', 'ù', 'ů', 'ʉ', 'ú', 'ȗ', 'ü', 'û', 'ũ', 'ụ'),
        'v': ('ᶌ', 'ṿ', 'ᴠ', 'ⱴ', 'ⱱ', 'ṽ'), 'w': ('ᴡ', 'ẇ', 'ẅ', 'ẃ', 'ẘ', 'ẉ', 'ⱳ', 'ŵ', 'ẁ'),
        'x': ('ẋ', 'ẍ'), 'y': ('ŷ', 'ÿ', 'ʏ', 'ẏ', 'ɏ', 'ƴ', 'ȳ', 'ý', 'ỿ', 'ỵ'),
        'z': ('ž', 'ƶ', 'ẓ', 'ẕ', 'ⱬ', 'ᴢ', 'ż', 'ź', 'ʐ'), 'ae': ('æ',), 'oe': ('œ',),
    }
    # glyphs_ascii: ASCII-to-ASCII homoglyphs (e.g., 'o' to '0')
    glyphs_ascii: Dict[str, Tuple[str, ...]] = {
        '0': ('o',), '1': ('l', 'i'), '3': ('8',), '6': ('9',), '8': ('3',), '9': ('6',), 'b': ('d', 'lb'), 'c': ('e',),
        'd': ('b', 'cl', 'dl'), 'e': ('c',), 'g': ('q',), 'h': ('lh',), 'i': ('1', 'l'), 'k': ('lc',), 'l': ('1', 'i'),
        'm': ('n', 'nn', 'rn'), 'n': ('m', 'r'), 'o': ('0',), 'q': ('g',), 'u': ('v',), 'v': ('u',), 'w': ('vv',),
        'rn': ('m',), 'cl': ('d',),
    }
    # latin_to_cyrillic: Latin characters to visually similar Cyrillic characters
    latin_to_cyrillic: Dict[str, str] = {
        'a': 'а', 'b': 'ь', 'c': 'с', 'd': 'ԁ', 'e': 'е', 'g': 'ԍ', 'h': 'һ', 'i': 'і', 'j': 'ј', 'k': 'к',
        'l': 'ӏ', 'm': 'м', 'o': 'о', 'p': 'р', 'q': 'ԛ', 's': 'ѕ', 't': 'т', 'v': 'ѵ', 'w': 'ԝ', 'x': 'х', 'y': 'у',
    }
    # Keyboard layouts for simulating adjacent key press errors
    qwerty = {'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9', 'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0', 'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'}
    qwertz = {'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9', 'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0', 'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop', 'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'}
    azerty = {'1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9', 'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m', 'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp', 'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'}
    keyboards: List[Dict[str, str]] = [qwerty, qwertz, azerty] # List of available keyboard layouts

    # default_tlds: A list of common TLDs used for the TLD-swap fuzzer if no custom list is provided.
    default_tlds: List[str] = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'co', 'io', 'biz', 'info', 'me', 'tv', 'name', 'co.uk', 'us', 'ca', 'de', 'fr', 'au', 'it', 'jp', 'in', 'br', 'ru', 'cn', 'es', 'mx', 'se', 'pl', 'ch', 'nl', 'be', 'at', 'kr', 'fi', 'dk', 'cz', 'hu', 'ro', 'gr', 'bg', 'ua', 'tw', 'hk', 'sa', 'ae', 'za', 'ke', 'ng', 'eg', 'pk', 'vn', 'th', 'id', 'ph', 'lk', 'my', 'np', 'lt', 'lv', 'ee', 'pt', 'il', 'kz', 'iq', 'qa', 'sy', 'om', 'ly', 'ye', 'bh', 'sd', 'jo', 'tn', 'dz', 'ma', 'gh', 'bd', 'ga', 'gq', 'tk', 'cf', 'ooo', 'xyz', 'online', 'site', 'wang', 'work', 'rest', 'buzz', 'fit', 'news', 'to', 'no', 'al', 'ir', 'cl', 'cc', 'sg', 'pe', 'rs', 'club', 'si', 'mobi', 'by', 'cat', 'wiki', 'la', 'xxx', 'hr', 'jobs', 'ug', 'is', 'pro', 'fm', 'tips', 'ms', 'app']
    # common_dictionary_words: Words frequently used in domain names, especially for phishing or typosquatting.
    common_dictionary_words: List[str] = ['auth', 'access', 'account', 'admin', 'agree', 'blue', 'business', 'cdn', 'choose', 'claim', 'cl', 'click', 'confirm', 'confirmation', 'connect', 'download', 'enroll', 'find', 'group', 'http', 'https', 'https-www', 'install', 'login', 'mobile', 'mail', 'my', 'online', 'pay', 'payment', 'payments', 'portal', 'recovery', 'register', 'ssl', 'safe', 'secure', 'security', 'service', 'services', 'signin', 'signup', 'support', 'summary', 'update', 'user', 'verify', 'verification', 'view', 'ww', 'www', 'web', 'actif', 'active', 'activite', 'agent', 'bleu', 'carte', 'compte', 'enligne', 'forum', 'fr', 'gerer', 'gouv', 'groupe', 'index', 'le', 'ma', 'menu', 'mon', 'moncompte', 'portail', 'site', 'solutions', 'autoryzacja', 'konto', 'logowanie', 'ssl']
    # BITSQUATTING_ALLOWED_CHARS: Character set allowed in domain parts generated by bitsquatting.
    BITSQUATTING_ALLOWED_CHARS = set('abcdefghijklmnopqrstuvwxyz0123456789-')

    def __init__(self,
                 domain: str,
                 dictionary: Optional[List[str]] = None,
                 tld_dictionary: Optional[List[str]] = None) -> None:
        """
        Initializes the Fuzzer with a target domain and optional custom dictionaries.

        Args:
            domain (str): The target domain string (e.g., "www.example.com").
            dictionary (Optional[List[str]]): A list of words for dictionary-based fuzzing.
                                              Defaults to `common_dictionary_words`.
            tld_dictionary (Optional[List[str]]): A list of TLDs for TLD swapping.
                                                 Defaults to `default_tlds`.

        Raises:
            ValueError: If the input domain is empty or a valid domain part cannot be extracted.
        """
        if not domain:
            raise ValueError("Input domain cannot be empty")

        # Split the input domain into subdomain, main domain part, and TLD
        self.subdomain, domain_part, self.tld = domain_tld(domain)

        try:
            # Decode the main domain part from Punycode to Unicode (if applicable)
            self.domain: str = idna.decode(domain_part) if domain_part else ''
        except idna.IDNAError as e:
            # Handle errors if the domain part is an invalid IDN
            raise ValueError(f"Invalid domain part '{domain_part}': {e}") from e

        # Further validation after attempting to decode
        if not self.domain and domain_part:
            raise ValueError(f"Could not extract valid unicode domain part from '{domain_part}' for input '{domain}'")
        elif not self.domain and not domain_part and not self.subdomain: # e.g. input like ".com" or just "com"
            raise ValueError(f"No valid domain or subdomain found in input '{domain}'")

        # Initialize dictionaries, using defaults if custom ones are not provided
        # Copies are made to prevent modification of the original lists if passed externally.
        self.dictionary: List[str] = list(dictionary) if dictionary is not None else self.common_dictionary_words
        self.tld_dictionary: List[str] = list(tld_dictionary) if tld_dictionary is not None else self.default_tlds

        # Stores the generated unique domain permutations
        self.domains: Set[Permutation] = set()

    # --- Fuzzing Strategy Methods (Refactored to accept text_to_fuzz) ---

    def _bitsquatting(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Generates variations of `text_to_fuzz` by flipping single bits in its ASCII characters.

        Args:
            text_to_fuzz (str): The string to apply bitsquatting to.

        Yields:
            str: Variations of the input string with one bit flipped if the
                 resulting character is a valid hostname character.
        """
        if not text_to_fuzz: return # No text to fuzz
        masks = [1 << i for i in range(8)] # Bitmasks for 0 through 7
        try:
            # Encode to ASCII, ignoring non-ASCII characters for basic bitsquatting
            text_bytes = text_to_fuzz.encode('ascii', errors='ignore')
        except UnicodeEncodeError:
             return # Should be caught by errors='ignore' but as a safeguard
        if not text_bytes: return # All characters were non-ASCII

        for i, byte_val in enumerate(text_bytes):
            for mask in masks:
                flipped_val = byte_val ^ mask # XOR to flip the bit
                flipped_char = chr(flipped_val)
                # Check if the new character is allowed in bitsquatted hostnames
                if flipped_char in self.BITSQUATTING_ALLOWED_CHARS:
                    # Reconstruct the string with the flipped character
                    yield text_bytes[:i].decode('ascii', 'ignore') + \
                          flipped_char + \
                          text_bytes[i + 1:].decode('ascii', 'ignore')

    def _cyrillic(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Replaces Latin characters in `text_to_fuzz` with visually similar Cyrillic characters.

        Args:
            text_to_fuzz (str): The string to apply Cyrillic homoglyph substitution to.

        Yields:
            str: Variations of the input string with one or more Latin characters
                 replaced by their Cyrillic counterparts.
        """
        if not text_to_fuzz: return
        # Identify characters that have Cyrillic homoglyphs
        replaceable = [(idx, self.latin_to_cyrillic[char])
                       for idx, char in enumerate(text_to_fuzz)
                       if char in self.latin_to_cyrillic]
        if not replaceable: return # No characters to replace

        original_list = list(text_to_fuzz)
        # Generate all combinations of replacements (1 char, 2 chars, etc.)
        for k in range(1, len(replaceable) + 1):
            for combo in itertools.combinations(replaceable, k):
                temp_list = list(original_list) # Create a mutable copy
                for index, replacement_char in combo:
                    temp_list[index] = replacement_char # Apply replacement
                yield "".join(temp_list)

    def _homoglyph(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Replaces characters in `text_to_fuzz` with visually similar ASCII or Unicode characters (homoglyphs).
        Considers general homoglyphs and TLD-specific allowed IDN characters.

        Args:
            text_to_fuzz (str): The string to apply homoglyph substitution to.

        Yields:
            str: Variations of the input string with characters replaced by homoglyphs.
        """
        if not text_to_fuzz: return

        # Get TLD-specific glyph rules based on the fuzzer's overall TLD context
        tld_specific_glyphs = self.glyphs_idn_by_tld.get(self.tld, {})
        combined_glyphs: Dict[str, Set[str]] = {} # Stores all applicable glyphs

        # Helper to merge glyph sources into combined_glyphs
        def _add_glyphs_to_combined_map(source_map: Dict[str, Tuple[str, ...]]):
            for char_key, glyph_options_tuple in source_map.items():
                combined_glyphs.setdefault(char_key, set()).update(glyph_options_tuple)

        # Order of adding matters if there are overlaps; later additions can expand sets.
        _add_glyphs_to_combined_map(self.glyphs_ascii)     # ASCII lookalikes
        _add_glyphs_to_combined_map(self.glyphs_unicode)   # General Unicode homoglyphs
        _add_glyphs_to_combined_map(tld_specific_glyphs) # TLD-specific IDN characters

        text_list = list(text_to_fuzz)
        for i, char_in_text in enumerate(text_list):
            if char_in_text in combined_glyphs:
                original_char_at_pos = text_list[i] # Save original character at this position
                for glyph in combined_glyphs[char_in_text]:
                    if glyph == original_char_at_pos: continue # Skip replacing a char with itself
                    text_list[i] = glyph # Apply homoglyph
                    yield "".join(text_list)
                text_list[i] = original_char_at_pos # Restore for next iteration/character

    def _hyphenation(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Inserts hyphens at various positions within `text_to_fuzz`.

        Args:
            text_to_fuzz (str): The string to hyphenate.

        Yields:
            str: Variations of the input string with a hyphen inserted.
        """
        if not text_to_fuzz: return
        # Iterate through possible insertion points (not at the very start or end directly)
        for i in range(1, len(text_to_fuzz)):
            # Avoid creating double hyphens or hyphen next to existing start/end
            if text_to_fuzz[i - 1] != '-' and text_to_fuzz[i] != '-':
                yield text_to_fuzz[:i] + '-' + text_to_fuzz[i:]

    def _insertion(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Simulates accidental insertion of adjacent keys on a keyboard within `text_to_fuzz`.

        Args:
            text_to_fuzz (str): The string to apply keyboard insertion errors to.

        Yields:
            str: Variations with an adjacent keyboard character inserted.
        """
        if not text_to_fuzz: return
        for i, orig_char_in_text in enumerate(text_to_fuzz):
            adjacent_keyboard_chars = set()
            # Collect adjacent characters from all defined keyboard layouts
            for keyboard_layout in self.keyboards:
                adjacent_keyboard_chars.update(keyboard_layout.get(orig_char_in_text, ''))

            prefix = text_to_fuzz[:i]
            current_char_str = text_to_fuzz[i] # The character at the current position
            suffix = text_to_fuzz[i + 1:]

            for char_to_insert in adjacent_keyboard_chars:
                # Insert before the original character
                yield prefix + char_to_insert + current_char_str + suffix
                # Insert after the original character
                yield prefix + current_char_str + char_to_insert + suffix

    def _omission(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Simulates accidental omission of a character from `text_to_fuzz`.

        Args:
            text_to_fuzz (str): The string to apply character omission to.

        Yields:
            str: Variations with one character removed.
        """
        if not text_to_fuzz or len(text_to_fuzz) <= 1: return # Cannot omit if 0 or 1 char
        for i in range(len(text_to_fuzz)):
            yield text_to_fuzz[:i] + text_to_fuzz[i + 1:] # Concatenate parts excluding char at i

    def _repetition(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Simulates accidental repetition (double-typing) of a character in `text_to_fuzz`.

        Args:
            text_to_fuzz (str): The string to apply character repetition to.

        Yields:
            str: Variations with one character repeated.
        """
        if not text_to_fuzz: return
        for i, char_in_text in enumerate(text_to_fuzz):
            # Insert the character again at its current position
            yield text_to_fuzz[:i] + char_in_text + text_to_fuzz[i:]

    def _replacement(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Simulates replacing a character in `text_to_fuzz` with an adjacent key from a keyboard.

        Args:
            text_to_fuzz (str): The string to apply keyboard replacement errors to.

        Yields:
            str: Variations with one character replaced by an adjacent keyboard key.
        """
        if not text_to_fuzz: return
        for i, orig_char_in_text in enumerate(text_to_fuzz):
            replacement_keyboard_chars = set()
            # Collect replacement characters from all layouts
            for keyboard_layout in self.keyboards:
                replacement_keyboard_chars.update(keyboard_layout.get(orig_char_in_text, ''))

            prefix = text_to_fuzz[:i]
            suffix = text_to_fuzz[i + 1:]
            for replacement_char in replacement_keyboard_chars:
                if replacement_char != orig_char_in_text: # Ensure actual replacement
                    yield prefix + replacement_char + suffix

    def _subdomain_fuzzer(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Inserts a dot into `text_to_fuzz` to create a structure resembling an additional subdomain level.
        E.g., "example" becomes "ex.ample".

        Args:
            text_to_fuzz (str): The string to operate on.

        Yields:
            str: Variations with an inserted dot.
        """
        if not text_to_fuzz or len(text_to_fuzz) < 2: return # Need at least 2 chars to insert a dot
        for i in range(1, len(text_to_fuzz)):
            # Avoid dots next to existing dots or hyphens, or at the very start/end if text_to_fuzz was part of a larger FQDN.
            if text_to_fuzz[i] != '.' and text_to_fuzz[i - 1] != '.' and \
               text_to_fuzz[i] != '-' and text_to_fuzz[i - 1] != '-':
                yield text_to_fuzz[:i] + '.' + text_to_fuzz[i:]

    def _transposition(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Simulates accidental transposition (swapping) of adjacent characters in `text_to_fuzz`.

        Args:
            text_to_fuzz (str): The string to apply character transposition to.

        Yields:
            str: Variations with two adjacent characters swapped.
        """
        if not text_to_fuzz or len(text_to_fuzz) < 2: return # Need at least 2 chars to transpose
        text_list = list(text_to_fuzz) # Convert to list for mutable operations
        for i in range(len(text_list) - 1):
            if text_list[i] == text_list[i + 1]: continue # Skip swapping identical adjacent chars

            # Swap characters
            text_list[i], text_list[i + 1] = text_list[i + 1], text_list[i]
            yield "".join(text_list)
            # Swap back to original state for the next iteration
            text_list[i], text_list[i + 1] = text_list[i + 1], text_list[i]

    def _vowel_swap(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Replaces vowels in `text_to_fuzz` with other vowels.

        Args:
            text_to_fuzz (str): The string to apply vowel swapping to.

        Yields:
            str: Variations with vowels replaced by other vowels.
        """
        if not text_to_fuzz: return
        vowels = 'aeiou'
        text_list = list(text_to_fuzz)
        for i, char_in_text in enumerate(text_list):
            if char_in_text in vowels:
                original_vowel_at_pos = text_list[i]
                for target_vowel in vowels:
                    if target_vowel != original_vowel_at_pos: # Ensure actual swap
                        text_list[i] = target_vowel
                        yield "".join(text_list)
                text_list[i] = original_vowel_at_pos # Restore for next iteration

    def _plural(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Adds 's' or 'es' (based on simple rules) at positions within `text_to_fuzz`.
        This is less common for direct typosquatting but adds variation.

        Args:
            text_to_fuzz (str): The string to pluralize internally.

        Yields:
            str: Variations with 's' or 'es' inserted.
        """
        # Original arbitrary minimum length for this fuzzer to apply
        if not text_to_fuzz or len(text_to_fuzz) < 5: return
        # Iterate within a specific range (original logic: 2nd char to 2nd-to-last char)
        for i in range(2, len(text_to_fuzz) - 2):
            plural_suffix = 'es' if text_to_fuzz[i] in ('s', 'x', 'z') else 's'
            yield text_to_fuzz[:i + 1] + plural_suffix + text_to_fuzz[i + 1:]

    def _addition(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Adds a single alphanumeric character to the end of `text_to_fuzz`,
        or around hyphens if present.

        Args:
            text_to_fuzz (str): The string to append characters to.

        Yields:
            str: Variations with an added character.
        """
        # Allow adding to empty string, e.g., if an empty subdomain is being fuzzed.
        # if not text_to_fuzz: return # Removed to allow adding to empty strings.

        alphanumeric_chars = [chr(i) for i in (*range(ord('a'), ord('z') + 1), *range(ord('0'), ord('9') + 1))]

        # Add to the end of the string
        for char_to_add in alphanumeric_chars:
            yield text_to_fuzz + char_to_add

        # If the string contains a hyphen, add characters around it
        if '-' in text_to_fuzz:
            for i, char_in_text in enumerate(text_to_fuzz):
                if char_in_text == '-':
                    prefix = text_to_fuzz[:i] # Part before hyphen
                    suffix = text_to_fuzz[i + 1:] # Part after hyphen
                    for char_to_add in alphanumeric_chars:
                        # Variation: prefix-charAddedSuffix
                        yield prefix + '-' + char_to_add + suffix
                    if i > 0: # Ensure there's a character before the hyphen to attach to
                        prefix_before_hyphen_group = text_to_fuzz[:i - 1]
                        char_directly_before_hyphen = text_to_fuzz[i - 1]
                        for char_to_add in alphanumeric_chars:
                            # Variation: prefixCharBeforeHyphencharAdded-suffix
                            yield prefix_before_hyphen_group + char_directly_before_hyphen + char_to_add + '-' + suffix

    def _dictionary(self, text_to_fuzz: str) -> Generator[str, None, None]:
        """
        Prepends or appends words from `self.dictionary` to `text_to_fuzz`,
        with and without hyphens. Also handles replacements around existing hyphens.

        Args:
            text_to_fuzz (str): The string to combine with dictionary words.
                                If empty, yields dictionary words themselves.
        Yields:
            str: Variations combined with dictionary words.
        """
        for word_from_dict in self.dictionary:
            if not word_from_dict: continue # Skip empty words in the dictionary

            if text_to_fuzz:
                # Prepend word
                yield word_from_dict + text_to_fuzz
                yield word_from_dict + '-' + text_to_fuzz
                # Append word
                yield text_to_fuzz + word_from_dict
                yield text_to_fuzz + '-' + word_from_dict
            else:
                # If text_to_fuzz is empty, a common case for empty subdomains,
                # yield the dictionary word itself as a potential subdomain.
                yield word_from_dict

        # Handle replacements if text_to_fuzz contains hyphens
        if text_to_fuzz and '-' in text_to_fuzz:
            parts = text_to_fuzz.split('-')
            if len(parts) > 1: # Ensure there are at least two parts (one hyphen)
                first_part = parts[0]
                last_part = parts[-1]
                # Reconstruct middle part, handling cases with multiple hyphens
                middle_join_char = "-" if len(parts) > 2 else ""
                middle_parts_str = middle_join_char.join(parts[1:-1])

                for word_from_dict in self.dictionary:
                    if not word_from_dict: continue

                    # Variation: firstPart-middleParts-dictionaryWord
                    if middle_parts_str:
                        yield f"{first_part}-{middle_parts_str}-{word_from_dict}"
                    else: # Only two parts: firstPart-dictionaryWord
                        yield f"{first_part}-{word_from_dict}"

                    # Variation: dictionaryWord-middleParts-lastPart
                    if middle_parts_str:
                        yield f"{word_from_dict}-{middle_parts_str}-{last_part}"
                    else: # Only two parts: dictionaryWord-lastPart
                        yield f"{word_from_dict}-{last_part}"

    # --- Main Generation Method (Integrates refactored fuzzers) ---
    def generate(self, fuzzers: Optional[List[str]] = None) -> None:
        """
        Generates domain permutations using selected fuzzing strategies.
        Applies core fuzzers to both the main domain part and the subdomain part.

        Args:
            fuzzers (Optional[List[str]]): A list of fuzzer technique names to run.
                If None or empty, a default set of fuzzers is used.
                Special fuzzer names:
                - '*original': Includes the original, unmodified domain.
                - 'tld-swap': Generates variations by swapping TLDs.
                - 'various': Generates common structural domain variations.
                Core fuzzers (like 'bitsquatting', 'homoglyph', etc.) are applied to
                both `self.domain` and `self.subdomain` (if present).
        """
        self.domains.clear() # Reset any domains from previous runs

        # Define the default set of fuzzers if none are specified by the user
        default_fuzzer_list = [
            'addition', 'bitsquatting', 'cyrillic', 'homoglyph', 'hyphenation',
            'insertion', 'omission', 'plural', 'repetition', 'replacement',
            'subdomain_fuzzer', # Method that inserts dots
            'transposition', 'vowel-swap', 'dictionary',
            'tld-swap', 'various', '*original' # Special handlers
        ]
        # Determine which fuzzers are active for this run
        active_fuzzers_set = set(fuzzers) if fuzzers is not None else set(default_fuzzer_list)

        # Map fuzzer names to their corresponding (refactored) methods
        core_fuzzer_method_map = {
            'addition': self._addition, 'bitsquatting': self._bitsquatting,
            'cyrillic': self._cyrillic, 'homoglyph': self._homoglyph,
            'hyphenation': self._hyphenation, 'insertion': self._insertion,
            'omission': self._omission, 'plural': self._plural,
            'repetition': self._repetition, 'replacement': self._replacement,
            'subdomain_fuzzer': self._subdomain_fuzzer, # Note: this specific fuzzer inserts dots
            'transposition': self._transposition, 'vowel-swap': self._vowel_swap,
            'dictionary': self._dictionary,
        }

        # --- Execute Core Fuzzing Techniques ---
        for fuzzer_name_key, fuzzer_method in core_fuzzer_method_map.items():
            if fuzzer_name_key in active_fuzzers_set:
                # 1. Apply fuzzer to the main domain part (self.domain)
                # self.domain should be a valid, non-empty string due to __init__ checks
                # print(f"DEBUG: Fuzzing domain part '{self.domain}' with '{fuzzer_name_key}'")
                try:
                    for domain_variation_part in fuzzer_method(self.domain):
                        self._add_permutation(
                            fuzzer_name=f"{fuzzer_name_key}-domain",
                            sub_part=self.subdomain, # Original subdomain
                            dom_part=domain_variation_part, # Fuzzed domain part
                            tld_part=self.tld # Original TLD
                        )
                except Exception as e: # Catch broad exceptions from fuzzing methods
                    # print(f"WARNING: Error during fuzzing domain part '{self.domain}' with {fuzzer_name_key}: {e}")
                    pass



        # --- Handle Special Fuzzer Types ---

        # '*original': Include the original, unmodified domain
        if '*original' in active_fuzzers_set:
            self._add_permutation(
                fuzzer_name='*original',
                sub_part=self.subdomain,
                dom_part=self.domain,
                tld_part=self.tld
            )

        # 'tld-swap': Generate variations by changing the TLD
        if 'tld-swap' in active_fuzzers_set:
            # Use TLDs from tld_dictionary, excluding the original TLD
            tlds_for_swapping = {t for t in self.tld_dictionary if t and t != self.tld}
            for new_tld in tlds_for_swapping:
                self._add_permutation(
                    fuzzer_name='tld-swap',
                    sub_part=self.subdomain,
                    dom_part=self.domain,
                    tld_part=new_tld
                )

        # 'various': Generate common structural variations
        if 'various' in active_fuzzers_set:
            original_domain_part = self.domain
            original_subdomain_part = self.subdomain
            original_tld_part = self.tld

            # Variation: If original TLD has a dot (e.g., "co.uk"), use only the last part (e.g., "uk")
            if '.' in original_tld_part:
                simplified_tld = original_tld_part.split('.')[-1]
                self._add_permutation('various-tld-simplify', original_subdomain_part, original_domain_part, simplified_tld)
                # Variation: Combine domain and TLD parts (e.g., "exampleco.uk" with "uk" TLD)
                self._add_permutation('various-tld-combine', original_subdomain_part, original_domain_part + original_tld_part.replace('.', ''), simplified_tld)

            # Variations if original TLD does *not* have a dot
            if '.' not in original_tld_part:
                # Variation: "domainTLD.TLD" (e.g., "examplecom.com")
                self._add_permutation('various-tld-append', original_subdomain_part, original_domain_part + original_tld_part, original_tld_part)
                # Variations appending ".com" if original TLD wasn't "com"
                if original_tld_part != 'com':
                    self._add_permutation('various-tld-hyphen-com', original_subdomain_part, original_domain_part + '-' + original_tld_part, 'com')
                    self._add_permutation('various-tld-append-com', original_subdomain_part, original_domain_part + original_tld_part, 'com')

            # Variations involving the subdomain part
            if original_subdomain_part:
                # Treat combined "subdomainPARTdomainPART" as the new main domain part, no subdomain
                self._add_permutation('various-sub-dom-combine', "", original_subdomain_part + original_domain_part, original_tld_part)
                self._add_permutation('various-sub-dom-combine-nodots', "", original_subdomain_part.replace('.', '') + original_domain_part, original_tld_part)
                self._add_permutation('various-sub-dom-hyphen', "", original_subdomain_part + '-' + original_domain_part, original_tld_part)
                self._add_permutation('various-sub-dom-hyphen-nodots', "", original_subdomain_part.replace('.', '-') + '-' + original_domain_part, original_tld_part)
            else:
                # If no original subdomain, suggest "www" as a common one
                self._add_permutation('various-add-www', "www", original_domain_part, original_tld_part)

    # --- Helper Method to Add Permutations ---
    def _add_permutation(self, fuzzer_name: str, sub_part: str, dom_part: str, tld_part: str) -> None:
        """
        Constructs a full domain string, encodes it to Punycode, validates it,
        and if valid, adds it as a Permutation object to `self.domains`.

        Args:
            fuzzer_name (str): The name of the fuzzer technique used.
            sub_part (str): The subdomain component. Can be empty.
            dom_part (str): The main domain component. Must not be empty.
            tld_part (str): The top-level domain component. Must not be empty.
        """
        # Core domain part and TLD are essential for a valid permutation
        if not dom_part or not tld_part:
            # print(f"DEBUG: Skipping permutation due to missing domain or TLD part. Fuzzer: {fuzzer_name}, Sub: '{sub_part}', Dom: '{dom_part}', Tld: '{tld_part}'")
            return

        # Build the full domain string, filtering out empty parts if sub_part is empty
        # Subdomain can be empty, domain and TLD cannot (enforced by check above)
        domain_components = []
        if sub_part: domain_components.append(sub_part)
        domain_components.append(dom_part)
        domain_components.append(tld_part)
        full_domain_unicode = '.'.join(domain_components)

        # Additional sanity checks for the constructed Unicode string
        if not full_domain_unicode or full_domain_unicode.startswith('.'):
            # print(f"DEBUG: Skipping permutation that is empty or starts with a dot. Fuzzer: {fuzzer_name}, Unicode: '{full_domain_unicode}'")
            return

        try:
            # Encode the Unicode domain to its ASCII (Punycode) representation
            # uts46=True applies stricter IDNA 2008 rules.
            full_domain_ascii = idna.encode(full_domain_unicode, uts46=True).decode('ascii')

            # Check for excessive length (common DNS limit)
            if len(full_domain_ascii) > 253:
                # print(f"DEBUG: Skipping domain exceeding 253 characters: {full_domain_ascii}")
                return

            # Validate against a Fully Qualified Domain Name (FQDN) regex
            if VALID_FQDN_REGEX.match(full_domain_ascii):
                # If valid, create a Permutation object and add to the set (handles duplicates)
                perm = Permutation(fuzzer=fuzzer_name, domain=full_domain_ascii)
                self.domains.add(perm)
            # else:
                # print(f"DEBUG: Skipping domain failing FQDN regex: {full_domain_ascii}")

        except (idna.IDNAError, UnicodeError):
            # Errors during encoding (e.g., invalid characters for IDN)
            # print(f"DEBUG: Skipping due to IDNA/Unicode encoding error: {full_domain_unicode}")
            pass
        except Exception: # Catch any other unexpected errors during processing
            # print(f"WARNING: Unexpected error processing permutation for '{full_domain_unicode}': {e}")
            pass

    # --- Method to Retrieve Generated Permutations ---
    def permutations(self,
                     registered: bool = False,
                     unregistered: bool = False,
                     dns_all: bool = False,
                     unicode: bool = False) -> List[Permutation]:
        """
        Returns the generated domain permutations, with optional filtering and formatting.

        Args:
            registered (bool): If True, only return domains inferred to be registered
                               (based on `Permutation.is_registered()`).
            unregistered (bool): If True, only return domains inferred to be unregistered.
                                 If both `registered` and `unregistered` are False (default)
                                 or both are True, all domains are returned.
            dns_all (bool): If False (default), trims DNS records (if present in Permutation objects)
                            to only the first entry of each type (A, AAAA, MX, NS).
            unicode (bool): If True, decodes domain names from Punycode back to Unicode
                            for display purposes.

        Returns:
            List[Permutation]: A sorted list of Permutation objects.
        """
        # Filter domains based on (inferred) registration status
        if registered and not unregistered:
            # Only registered domains
            domain_selection = [p for p in self.domains if p.is_registered()]
        elif unregistered and not registered:
            # Only unregistered domains
            domain_selection = [p for p in self.domains if not p.is_registered()]
        else:
            # All domains (if both flags are same or default)
            domain_selection = list(self.domains)

        # Work on copies to avoid modifying the original Permutation objects in self.domains
        processed_domains = [p.copy() for p in domain_selection]

        # Trim DNS records if `dns_all` is False
        if not dns_all:
            def _trim_dns_records(p: Permutation) -> Permutation:
                # Check if domain is considered registered (likely to have DNS data)
                if p.is_registered():
                    for dns_record_key in ('dns_ns', 'dns_a', 'dns_aaaa', 'dns_mx'):
                        if dns_record_key in p:
                            # Ensure the record value is a list and not empty before slicing
                            record_value = p.get(dns_record_key)
                            if isinstance(record_value, list) and record_value:
                                p[dns_record_key] = record_value[:1] # Keep only the first record
                return p
            processed_domains = list(map(_trim_dns_records, processed_domains))

        # Decode domain names to Unicode if requested
        if unicode:
            def _decode_domain_to_unicode(p: Permutation) -> Permutation:
                try:
                    domain_value_ascii = p.get('domain')
                    # Ensure 'domain' exists and is a string before attempting decode
                    if isinstance(domain_value_ascii, str):
                        p.domain = idna.decode(domain_value_ascii)
                except idna.IDNAError:
                    # If decoding fails (should be rare if encoding succeeded), keep the ASCII form.
                    pass
                return p
            processed_domains = list(map(_decode_domain_to_unicode, processed_domains))

        # Return the final list, sorted according to Permutation's __lt__ method
        return sorted(processed_domains)
