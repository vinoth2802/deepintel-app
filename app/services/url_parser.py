import urllib.parse
import idna
from app.config.dconfig import VALID_FQDN_REGEX


class UrlParser():
	def __init__(self, url):
		if not url:
			raise TypeError('argument has to be non-empty string')
		u = urllib.parse.urlparse(url if '://' in url else '//' + url, scheme='http')
		self.scheme = u.scheme.lower()
		if self.scheme not in ('http', 'https'):
			raise ValueError('invalid scheme') from None
		self.domain = u.hostname.lower()
		try:
			self.domain = idna.encode(self.domain).decode()
		except Exception:
			raise ValueError('invalid domain name') from None
		if not self._validate_domain(self.domain):
			raise ValueError('invalid domain name') from None
		self.username = u.username
		self.password = u.password
		self.port = u.port
		self.path = u.path
		self.query = u.query
		self.fragment = u.fragment

	def _validate_domain(self, domain):
		if len(domain) < 1 or len(domain) > 253:
			return False
		if VALID_FQDN_REGEX.match(domain):
			try:
				_ = idna.decode(domain)
			except Exception:
				return False
			else:
				return True
		return False

	def full_uri(self, domain=None):
		uri = '{}://'.format(self.scheme)
		if self.username:
			uri += self.username
			if self.password:
				uri += ':{}'.format(self.password)
			uri += '@'
		uri += self.domain if not domain else domain
		if self.port:
			uri += ':{}'.format(self.port)
		if self.path:
			uri += self.path
		if self.query:
			uri += '?{}'.format(self.query)
		if self.fragment:
			uri += '#{}'.format(self.fragment)
		return uri