

with open('C:/Users/bebxadvmmae/Desktop/test.txt', 'r') as f:
	seekOn = 0
	for x in xrange(0, -100, -1):
		f.seek(x, 2)
		if repr(f.readline()) == repr('\n'):
			if x + 1 < -4:
				break
	print repr(f.readline())