import re
import gzip
import urllib.request
from app.config.dconfig import  REQUEST_TIMEOUT_HTTP



class UrlOpener():
	def __init__(self, url, timeout=REQUEST_TIMEOUT_HTTP, headers={}, verify=True):
		http_headers = {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
			'accept-encoding': 'gzip,identity',
			'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8'}
		for h, v in headers.items():
			# do not override accepted encoding - only gzip,identity is supported
			if h.lower() != 'accept-encoding':
				http_headers[h.lower()] = v
		if verify:
			ctx = urllib.request.ssl.create_default_context()
		else:
			ctx = urllib.request.ssl._create_unverified_context()
		request = urllib.request.Request(url, headers=http_headers)
		with urllib.request.urlopen(request, timeout=timeout, context=ctx) as r:
			self.headers = r.headers
			self.code = r.code
			self.reason = r.reason
			self.url = r.url
			self.content = r.read()
		if self.content[:3] == b'\x1f\x8b\x08':
			self.content = gzip.decompress(self.content)
		if 64 < len(self.content) < 1024:
			try:
				meta_url = re.search(r'<meta[^>]*?url=(https?://[\w.,?!:;/*#@$&+=[\]()%~-]*?)"', self.content.decode(), re.IGNORECASE)
			except Exception:
				pass
			else:
				if meta_url:
					self.__init__(meta_url.group(1), timeout=timeout, headers=http_headers, verify=verify)
		self.normalized_content = self._normalize()

	def _normalize(self):
		content = b' '.join(self.content.split())
		mapping = dict({
			b'(action|src|href)=".+"': lambda m: m.group(0).split(b'=')[0] + b'=""',
			b'url(.+)': b'url()',
			})
		for pattern, repl in mapping.items():
			content = re.sub(pattern, repl, content, flags=re.IGNORECASE)
		return content