import time
with open('C:/wamp64/logs/access.log') as fileobject:
	fileobject.seek(2,0)
	while True:
		line = fileobject.readline()

		if line != '':
			print line
		else:
			time.sleep(1)