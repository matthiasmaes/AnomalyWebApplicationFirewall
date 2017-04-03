import time
with open('C:/wamp64/logs/access.log') as fileobject:
	fileobject.seek(0,2)

	while True:
		line = fileobject.readline()

		if line != '':
			print line
		else:
			time.sleep(1)