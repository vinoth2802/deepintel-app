from PIL import Image


class pHash():
	def __init__(self, image, hsize=8):
		img = Image.open(image).convert('L').resize((hsize, hsize), Image.LANCZOS)
		pixels = list(img.getdata())
		avg = sum(pixels) / len(pixels)
		self.hash = ''.join('1' if p > avg else '0' for p in pixels)

	def __sub__(self, other):
		bc = len(self.hash)
		ham = sum(x != y for x, y in list(zip(self.hash, other.hash)))
		e = 2.718281828459045
		sub = int((1 + e**((bc - ham) / bc) - e) * 100)
		return sub if sub > 0 else 0

	def __repr__(self):
		return '{:x}'.format(int(self.hash, base=2))

	def __int__(self):
		return int(self.hash, base=2)