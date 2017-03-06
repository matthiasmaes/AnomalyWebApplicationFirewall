from pymongo import MongoClient
import json
StreamMongoDB = MongoClient().Firewall.TestStream

# packet1 = '{"code" : "503","url" : "http://test.catapa.be/","ip" : "213.211.143.24","requestUrl" : "http://test.catapa.be/","time" : "21","date" : "14/Dec/2011","timezone" : "+0100","uagent" : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2","method" : "GET","size" : "1210"}'
# packet2 = '{"code" : "200","url" : "http://test.catapa.be/","ip" : "145.62.64.100","requestUrl" : "http://test.catapa.be/","time" : "21","date" : "14/Dec/2011","timezone" : "+0100","uagent" : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2","method" : "GET","size" : "1210"}'
# packet3 = '{"code" : "200","url" : "http://test.catapa.be/","ip" : "14.1.96.1","requestUrl" : "http://test.catapa.be/","time" : "21","date" : "14/Dec/2011","timezone" : "+0100","uagent" : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2","method" : "GET","size" : "1210"}'
# packet4 = '{"code" : "200","url" : "http://test.catapa.be/","ip" : "40.96.19.209","requestUrl" : "http://test.catapa.be/","time" : "21","date" : "14/Dec/2011","timezone" : "+0100","uagent" : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2","method" : "GET","size" : "1210"}'



while True:

	print '[1] (test.catapa.be, belgium, 21, Wednesday)'
	print '[2] (test.catapa.be, germany, 21, Wednesday)'
	print '[3] (test.catapa.be, china, 21, Wednesday)'
	print '[4] (test.catapa.be, finland, 21, Wednesday)'

	userInput = raw_input('Make your choice: ')

	if userInput == '1':
		StreamMongoDB.insert_one(json.loads(packet1))
		print 'imported'

	elif userInput == '2':
		StreamMongoDB.insert_one(json.loads(packet2))
		print 'imported'
	elif userInput == '3':
		StreamMongoDB.insert_one(json.loads(packet3))
		print 'imported'
	elif userInput == '4':
		StreamMongoDB.insert_one(json.loads(packet4))
		print 'imported'

	else:
		print 'Input not recognized'

	print '------------------------'