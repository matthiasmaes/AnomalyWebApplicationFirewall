import random

with open ('access.log', 'w+') as fileIO:

	for x in xrange(0,500):
		day = str(random.randint(1, 30))
		hour = str(random.randint(0, 23))
		minute = str(random.randint(0, 59))
		second = str(random.randint(0, 59))
		url = random.choice(['index', 'contact', 'about'])

		day = '0' + day if int(day) < 10 else day
		hour = '0' + hour if int(hour) < 10 else hour
		minute = '0' + minute if int(minute) < 10 else minute
		second = '0' + second if int(second) < 10 else second

		fileIO.write('::1 - - [' + day + '/Apr/2017:' + hour + ':' + minute + ':' + second + ' +0200] "GET /test/' +  url + '.html" 200 202575 "http://localhost:8080/test/' +  random.choice(['index', 'contact', 'about']) + '.html" "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36"\n')

		fileIO.write('::1 - - [' + day + '/Apr/2017:' + hour + ':' + minute + ':' + second + ' +0200] "GET /favicon.ico HTTP/1.1" 200 202575 "http://localhost:8080/test/' +  url + '.html" "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36"\n')