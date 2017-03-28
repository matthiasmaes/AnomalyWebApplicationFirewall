

with open('C:/Users/bebxadvmmae/Desktop/test.txt', 'r') as f:
	### TODO: first and last line won't be read
	seekOn = 0
	for x in xrange(0, -100, -1):
		try:
			f.seek(x, 2)
			if repr(f.readline()) == repr('\n'):
				if x + 1 < -4:
					break

		except Exception as e:
			print repr(f.readline())


	print repr(f.readline())