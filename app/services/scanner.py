import threading
import socket
import queue
from dns.resolver import Resolver, NXDOMAIN, NoNameservers
import dns.rdatatype
from dns.exception import DNSException
from io import BytesIO
import os
import tlsh
import geoip2 as geoip
import ppdeep as ssdeep
from urllib.request import urlopen as UrlOpener

from app.services.phash import pHash
from headless_browser import HeadlessBrowser  # Assuming this class exists in your project

from app.config.dconfig import REQUEST_TIMEOUT_SMTP, REQUEST_TIMEOUT_DNS, REQUEST_RETRIES_DNS, REQUEST_TIMEOUT_HTTP
from app.utils.domain_util import _debug


class Scanner(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self._stop_event = threading.Event()
		self.daemon = True
		self.id = 0
		self.jobs = queue
		self.lsh_init = ''
		self.lsh_effective_url = ''
		self.phash_init = None
		self.screenshot_dir = None
		self.url = None
		self.option_extdns = False
		self.option_geoip = False
		self.option_lsh = None
		self.option_phash = False
		self.option_banners = False
		self.option_mxcheck = False
		self.nameservers = []
		self.useragent = ''

	@staticmethod
	def _send_recv_tcp(host, port, data=b'', timeout=2.0, recv_bytes=1024):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)
		resp = b''
		try:
			sock.connect((host, port))
			if data:
				sock.send(data)
			resp = sock.recv(recv_bytes)
		except Exception as e:
			_debug(e)
		finally:
			sock.close()
		return resp.decode('utf-8', errors='ignore')

	def _banner_http(self, ip, vhost):
		response = self._send_recv_tcp(ip, 80,
			'HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n'.format(vhost, self.useragent).encode())
		if not response:
			return ''
		headers = response.splitlines()
		for field in headers:
			if field.lower().startswith('server: '):
				return field[8:]
		return ''

	def _banner_smtp(self, mx):
		response = self._send_recv_tcp(mx, 25)
		if not response:
			return ''
		hello = response.splitlines()[0]
		if hello.startswith('220'):
			return hello[4:].strip()
		return ''

	def _mxcheck(self, mxhost, domain_from, domain_rcpt):
		r'''
		Detects potential email honey pots waiting for mistyped emails to arrive.
		Note: Some mail servers only pretend to accept incorrectly addressed
		emails - this technique is used to prevent "directory harvesting attack".
		'''
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(REQUEST_TIMEOUT_SMTP)
			sock.connect((mxhost, 25))
		except Exception:
			return False
		for cmd in [
			'EHLO {}\r\n'.format(mxhost),
			'MAIL FROM: randombob1986@{}\r\n'.format(domain_from),
			'RCPT TO: randomalice1986@{}\r\n'.format(domain_rcpt),
			# And that's how the cookie crumbles
		]:
			try:
				resp = sock.recv(512)
			except Exception:
				break
			if not resp:
				break
			if resp[0] != 0x32: # status code != 2xx
				break
			sock.send(cmd.encode())
		else:
			sock.close()
			return True
		sock.close()
		return False

	def stop(self):
		self._stop_event.set()

	def is_stopped(self):
		return self._stop_event.is_set()

	def run(self):
		if self.option_extdns:
			if self.nameservers:
				resolv = Resolver(configure=False)
				resolv.nameservers = self.nameservers
			else:
				resolv = Resolver()
				resolv.search = []

			resolv.lifetime = REQUEST_TIMEOUT_DNS * REQUEST_RETRIES_DNS
			resolv.timeout = REQUEST_TIMEOUT_DNS
			EDNS_PAYLOAD = 1232
			resolv.use_edns(edns=True, ednsflags=0, payload=EDNS_PAYLOAD)
			resolv.rotate = True

			if hasattr(resolv, 'resolve'):
				resolve = resolv.resolve
			else:
				resolve = resolv.query

		if self.option_geoip:
			geo = geoip()

		if self.option_phash:
			browser = HeadlessBrowser(useragent=self.useragent)

		_answer_to_list = lambda ans: sorted([str(x).split(' ')[-1].rstrip('.') for x in ans])

		while not self.is_stopped():
			try:
				task = self.jobs.get(block=False)
			except queue.Empty:
				self.stop()
				return

			domain = task.get('domain')

			dns_a = False
			dns_aaaa = False
			if self.option_extdns:
				nxdomain = False
				dns_ns = False
				dns_mx = False

				try:
					task['dns_ns'] = _answer_to_list(resolve(domain, rdtype=dns.rdatatype.NS))
					dns_ns = True
				except NXDOMAIN:
					nxdomain = True
				except NoNameservers:
					task['dns_ns'] = ['!ServFail']
				except DNSException as e:
					_debug(e)

				if nxdomain is False:
					try:
						task['dns_a'] = _answer_to_list(resolve(domain, rdtype=dns.rdatatype.A))
						dns_a = True
					except NoNameservers:
						task['dns_a'] = ['!ServFail']
					except DNSException as e:
						_debug(e)

					try:
						task['dns_aaaa'] = _answer_to_list(resolve(domain, rdtype=dns.rdatatype.AAAA))
						dns_aaaa = True
					except NoNameservers:
						task['dns_aaaa'] = ['!ServFail']
					except DNSException as e:
						_debug(e)

				if nxdomain is False and dns_ns is True:
					try:
						task['dns_mx'] = _answer_to_list(resolve(domain, rdtype=dns.rdatatype.MX))
						dns_mx = True
					except NoNameservers:
						task['dns_mx'] = ['!ServFail']
					except DNSException as e:
						_debug(e)
			else:
				try:
					addrinfo = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
				except socket.gaierror as e:
					if e.errno == -3:
						task['dns_a'] = ['!ServFail']
				except Exception as e:
					_debug(e)
				else:
					for _, _, _, _, sa in addrinfo:
						ip = sa[0]
						if '.' in ip:
							if 'dns_a' not in task:
								task['dns_a'] = set()
								dns_a = True
							task['dns_a'].add(ip)
						if ':' in ip:
							if 'dns_aaaa' not in task:
								task['dns_aaaa'] = set()
								dns_aaaa = True
							task['dns_aaaa'].add(ip)
					if 'dns_a' in task:
						task['dns_a'] = list(task['dns_a'])
					if 'dns_aaaa' in task:
						task['dns_aaaa'] = list(task['dns_aaaa'])

			if self.option_mxcheck:
				if dns_mx is True:
					if domain != self.url.domain:
						if self._mxcheck(task['dns_mx'][0], self.url.domain, domain):
							task['mx_spy'] = True

			if self.option_geoip:
				if dns_a is True:
					try:
						country = geo.country_by_addr(task['dns_a'][0])
					except Exception as e:
						_debug(e)
						pass
					else:
						if country:
							task['geoip'] = country.split(',')[0]

			if self.option_banners:
				if dns_a is True:
					banner = self._banner_http(task['dns_a'][0], domain)
					if banner:
						task['banner_http'] = banner
				if dns_mx is True:
					banner = self._banner_smtp(task['dns_mx'][0])
					if banner:
						task['banner_smtp'] = banner

			if self.option_phash or self.screenshot_dir:
				if dns_a or dns_aaaa:
					try:
						browser.get(self.url.full_uri(domain))
						screenshot = browser.screenshot()
					except Exception as e:
						_debug(e)
					else:
						if self.option_phash:
							phash = pHash(BytesIO(screenshot))
							task['phash'] = self.phash_init - phash
						if self.screenshot_dir:
							filename = os.path.join(self.screenshot_dir, '{:08x}_{}.png'.format(self.id, domain))
							try:
								with open(filename, 'wb') as f:
									f.write(screenshot)
							except Exception as e:
								_debug(e)

			if self.option_lsh:
				if dns_a is True or dns_aaaa is True:
					try:
						r = UrlOpener(self.url.full_uri(domain),
							timeout=REQUEST_TIMEOUT_HTTP,
							headers={'user-agent': self.useragent},
							verify=False)
					except Exception as e:
						_debug(e)
					else:
						if r.url.split('?')[0] != self.lsh_effective_url:
							if self.option_lsh == 'ssdeep':
								lsh_curr = ssdeep.hash(r.normalized_content)
								if lsh_curr not in (None, '3::'):
									task['ssdeep'] = ssdeep.compare(self.lsh_init, lsh_curr)
							elif self.option_lsh == 'tlsh':
								lsh_curr = tlsh.hash(r.normalized_content)
								if lsh_curr not in (None, '', 'TNULL'):
									task['tlsh'] = int(100 - (min(tlsh.diff(self.lsh_init, lsh_curr), 300)/3))

			self.jobs.task_done()