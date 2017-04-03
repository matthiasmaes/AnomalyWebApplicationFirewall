import time
with open('C:/Users/bebxadvmmae/Desktop/TODO.txt') as fileobject:
	while True:
		line = fileobject.readline()
		print line

		time.sleep(1)