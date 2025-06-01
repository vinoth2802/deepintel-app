import socket
import re
from datetime import datetime, timezone
from dns import resolver
from dns.e164 import query  # Still present in your original code
from app.utils.domain_util import domain_tld

try:
    from dateutil import parser as date_parser
    USE_DATEUTIL = True
except ImportError:
    USE_DATEUTIL = False


class Whois:
    WHOIS_IANA = 'whois.iana.org'
    TIMEOUT = 2.0

    WHOIS_TLD = {
        'com': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'net': 'whois.verisign-grs.com',
        'edu': 'whois.educause.edu',
        'gov': 'whois.dotgov.gov',
        'mil': 'whois.nic.mil',
        'int': 'whois.iana.org',
        'co': 'whois.nic.co',
        'io': 'whois.nic.io',
        'biz': 'whois.biz',
        'info': 'whois.afilias.net',
        'me': 'whois.nic.me',
        'tv': 'tvwhois.verisign-grs.com',
        'name': 'whois.nic.name',
        'co.uk': 'whois.nic.uk',
        'us': 'whois.nic.us',
        'ca': 'whois.cira.ca',
        'de': 'whois.denic.de',
        'fr': 'whois.afnic.fr',
        'au': 'whois.auda.org.au',
        'it': 'whois.nic.it',
        'jp': 'whois.jprs.jp',
        'in': 'whois.registry.in',
        'br': 'whois.registro.br',
        'ru': 'whois.tcinet.ru',
        'cn': 'whois.cnnic.cn',
        'es': 'whois.nic.es',
        'mx': 'whois.mx',
        'se': 'whois.iis.se',
        'pl': 'whois.dns.pl',
        'ch': 'whois.nic.ch',
        'nl': 'whois.domain-registry.nl',
        'be': 'whois.dns.be',
        'at': 'whois.nic.at',
        'kr': 'whois.kr',
        'fi': 'whois.fi',
        'dk': 'whois.dk-hostmaster.dk',
        'cz': 'whois.nic.cz',
        'hu': 'whois.nic.hu',
        'ro': 'whois.rotld.ro',
        'gr': 'whois.ics.forth.gr',
        'bg': 'whois.register.bg',
        'ua': 'whois.ua',
        'tw': 'whois.twnic.net.tw',
        'hk': 'whois.hkirc.hk',
        'sa': 'whois.nic.net.sa',
        'ae': 'whois.aeda.net.ae',
        'za': 'whois.registry.net.za',
        'ke': 'whois.kenic.or.ke',
        'ng': 'whois.nic.net.ng',
        'eg': 'whois.ripe.net',
        'pk': 'whois.pknic.net.pk',
        'vn': 'whois.vnnic.vn',
        'th': 'whois.thnic.co.th',
        'id': 'whois.pandi.or.id',
        'ph': 'whois.dot.ph',
        'lk': 'whois.nic.lk',
        'my': 'whois.mynic.my',
        'np': 'whois.mos.com.np',
        'lt': 'whois.domreg.lt',
        'lv': 'whois.nic.lv',
        'ee': 'whois.tld.ee',
        'sk': 'whois.sk-nic.sk',
        'pt': 'whois.dns.pt',
        'il': 'whois.isoc.org.il',
        'kz': 'whois.nic.kz',
        'iq': 'whois.cmc.iq',
        'qa': 'whois.registry.qa',
        'sy': 'whois.tld.sy',
        'om': 'whois.registry.om',
        'ly': 'whois.nic.ly',
        'ye': 'whois.yemen.net.ye',
        'bh': 'whois.nic.bh',
        'sd': 'whois.sd',
        'jo': 'whois.jonic.org.jo',
        'tn': 'whois.ati.tn',
        'dz': 'whois.nic.dz',
        'ma': 'whois.iam.net.ma',
        'gh': 'whois.nic.gh',
        'bd': 'whois.btcl.net.bd',
    }

    def __init__(self):
        self.whois_tld = self.WHOIS_TLD.copy()

    def _parse_datetime(self, s):
        if USE_DATEUTIL:
            try:
                return date_parser.parse(s)
            except Exception:
                return None
        else:
            formats = (
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S%z',
                '%Y-%m-%d %H:%M',
                '%Y.%m.%d %H:%M',
                '%Y.%m.%d %H:%M:%S',
                '%d.%m.%Y %H:%M:%S',
                '%a %b %d %Y',
                '%d-%b-%Y',
                '%Y-%m-%d',
            )
            for fmt in formats:
                try:
                    return datetime.strptime(s, fmt)
                except ValueError:
                    continue
            return None

    def get_dns_records(self, domain):
        result = {}
        try:
            a_answers = resolver.resolve(domain, 'A')
            result['A'] = [r.address for r in a_answers]
        except:
            result['A'] = []

        try:
            mx_answers = resolver.resolve(domain, 'MX')
            result['MX'] = [str(r.exchange).rstrip('.') for r in mx_answers]
        except:
            result['MX'] = []

        return result


    def _extract(self, response):
        result = {'text': response}
        cleaned = '\n'.join(line.strip() for line in response.splitlines() if not line.strip().startswith('%'))

        field_patterns = {
            'domain_name': (r'^\s*(?:Domain Name|domain name|domain):\s*(?P<value>[^\r\n]+)', False),
            'registry_domain_id': (r'^\s*(?:Registry Domain ID):\s*(?P<value>[^\r\n]+)', False),
            'registrar_whois_server': (r'^\s*(?:Registrar WHOIS Server):\s*(?P<value>[^\r\n]+)', False),
            'registrant_name': (r'^\s*(?:Registrant Name|Admin Name|Tech Name|Name):\s*(?P<value>[^\r\n]+)', False),
            'registrant_organization': (
                r'^\s*(?:Registrant Organization|Admin Organization|Tech Organization|Organization|Company):\s*(?P<value>[^\r\n]+)',
                False),
            'registrant_email': (r'^\s*(?:Registrant Email|Admin Email|Tech Email|Email):\s*(?P<value>[^\r\n]+)',
                                 False),  # Add email too for comparison,
            'registrar_url': (r'^\s*(?:Registrar URL):\s*(?P<value>[^\r\n]+)', False),
            'updated_date': (r'^\s*(?:Updated Date):\s*(?P<value>[^\r\n]+)', False),
            'creation_date': (r'^\s*(?:Creation Date):\s*(?P<value>[^\r\n]+)', False),
            'registry_expiry_date': (r'^\s*(?:Registry Expiry Date):\s*(?P<value>[^\r\n]+)', False),
            'registrar': (r'^\s*(?:Registrar):\s*(?P<value>[^\r\n]+)', False),
            'registrar_iana_id': (r'^\s*(?:Registrar IANA ID):\s*(?P<value>[^\r\n]+)', False),
            'registrar_abuse_contact_email': (r'^\s*(?:Registrar Abuse Contact Email):\s*(?P<value>[^\r\n]+)', False),
            'registrar_abuse_contact_phone': (r'^\s*(?:Registrar Abuse Contact Phone):\s*(?P<value>[^\r\n]+)', False),
            'domain_status': (r'^\s*(?:Domain Status|Status):\s*(?P<value>[^\r\n]+)', True),
            'name_servers': (r'^\s*(?:Name Server|Name-Server|nserver):\s*(?P<value>[^\r\n]+)', True),
            'dnssec': (r'^\s*(?:DNSSEC):\s*(?P<value>[^\r\n]+)', False),
            'icann_whois_inaccuracy_complaint_form': (
                r'^\s*URL of the ICANN Whois Inaccuracy Complaint Form:\s*(?P<value>[^\r\n]+)', False),
            'last_update_of_whois_database': (r'^\s*Last update of whois database:\s*(?P<value>[^\r\n]+)', False),
        }

        unparsed_fields = {}

        for key, (pattern, multiple) in field_patterns.items():
            matches = re.findall(pattern, cleaned, flags=re.IGNORECASE | re.MULTILINE)
            if not matches:
                result[key] = [] if multiple else None
            elif multiple:
                result[key] = matches
            else:
                result[key] = matches[0]

            # Convert dates
            if key.endswith("date") and result[key]:
                try:
                    result[key] = self._parse_datetime(result[key])
                except Exception:
                    result[key] = None

        # Compute domain age if possible
        if isinstance(result.get('creation_date'), datetime):
            result['domain_age_days'] = (datetime.now(timezone.utc) - result['creation_date']).days
        else:
            result['domain_age_days'] = None

        # Extract leftover fields for diagnostics
        for line in cleaned.splitlines():
            parts = line.split(':', 1)
            if len(parts) == 2:
                k, v = parts[0].strip(), parts[1].strip()
                k_lower = k.lower()
                if all(k_lower not in p[0].lower() for p in field_patterns.values()):
                    unparsed_fields[k] = v

        result["unparsed_fields"] = unparsed_fields

        # DNS info if domain_name present
        domain = result.get("domain_name")
        if domain:
            dns_records = self.get_dns_records(domain)
            result['a_records'] = dns_records.get('A', [])
            result['mx_records'] = dns_records.get('MX', [])
        else:
            result['a_records'] = []
            result['mx_records'] = []

        return result

    def query(self, domain, server=None):
        _, _, tld = domain_tld(domain)
        server = server or self.whois_tld.get(tld, self.WHOIS_IANA)
        response = b''

        try:
            with socket.create_connection((server, 43), timeout=self.TIMEOUT) as sock:
                if server == 'whois.verisign-grs.com':
                    domain = '=' + domain
                sock.sendall(domain.encode() + b'\r\n')

                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data

        except (socket.timeout, socket.gaierror):
            return ''

        response_str = response.decode('utf-8', errors='ignore')

        refer = re.search(r'refer:\s+(?P<server>[-.a-z0-9]+)', response_str, re.IGNORECASE | re.MULTILINE)
        if refer:
            return self.query(domain, refer.group('server'))

        return response_str

    def whois(self, domain, server=None):
        return self._extract(self.query(domain, server))
