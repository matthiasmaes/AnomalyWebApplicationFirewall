import progressbar, string
import datetime
import threading
import calendar
import math
import IP2Location
import dns.resolver
from pymongo import MongoClient
from optparse import OptionParser
from record_app import Record_App


#### Init global vars ####
initTime = str('%02d' % datetime.datetime.now().hour) + ":" +  str('%02d' % datetime.datetime.now().minute) + ":" +  str('%02d' % datetime.datetime.now().second)
startTime = datetime.datetime.now()
converted, activeWorkers = 0, 0
weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']


#### Init options ####
parser = OptionParser()
parser.add_option("-p", "--ping", action="store_true", dest="ping", default=False, help="Try to resolve originating domains to ip for geolocation")
parser.add_option("-b", "--bot", action="store_true", dest="bot", default=False, help="Filter search engine bots")
parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="Show debug messages")
parser.add_option("-t", "--threads", action="store", dest="threads", default="16", help="Amout of threats that can be used")
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="250", help="Max lines per thread")
parser.add_option("-m", "--mongo", action="store", dest="inputMongo", default="DEMO", help="Input via mongo")

parser.add_option("-s", "--start", action="store", dest="startIndex", default="0", help="Start index for profiling")
parser.add_option("-e", "--end", action="store", dest="endindex", default="0", help="End index for profiling")

options, args = parser.parse_args()


#### Init DB ####
OutputMongoDB = MongoClient().profile_app['profile_app_' + initTime]
InputMongoDB = MongoClient().FormattedLogs[options.inputMongo]

#### Place index on url field to speed up searches through db ####
OutputMongoDB.create_index('url', background=True)

#### Determening lines to process####
options.endindex = InputMongoDB.count() if int(options.endindex) == 0 else int(options.endindex)
diffLines = int(options.endindex) - int(options.startIndex) + 1

#### Reading bot file ####
if options.bot:
	with open('sources/bots.txt') as f:
		bots = f.readlines()
	bots = [x.strip() for x in bots]

#### Preparing progress bar ####
progressBarObj = progressbar.ProgressBar(maxval=diffLines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
progressBarObj.start()



def GeoLocate(ip):
	""" Method for translating ip-address to geolocation (country) """

	try:
		IP2LocObj = IP2Location.IP2Location();
		IP2LocObj.open("sources\IP2GEODB.BIN");
		return IP2LocObj.get_all(ip).country_long;
	except Exception:
		if options.ping:
			try:
				return IP2LocObj.get_all(dns.resolver.query(ip, 'A')[0]).country_long;
			except Exception:
				return "Geolocation failed"
		else:
			return "Domain translation disabled"



def calculateRatio(url, metric, data):
	""" Method for calculating the ratio for a given metric """

	if data is not '' or data is not None:
		currRecord = OutputMongoDB.find_one({"url": url })
		OutputMongoDB.update({'url': url}, {'$set': { metric + '.' + data + '.ratio': float(currRecord[metric][data]['counter']) / float(currRecord['totalConnections'])}})
		for metricEntry in currRecord[metric]:
			OutputMongoDB.update({'url': url}, {'$set': {metric + '.' + metricEntry + '.ratio': float(currRecord[metric][metricEntry]['counter']) / float(currRecord['totalConnections'])}})



def processLine(start, index):
	""" Assign workers with workload """

	for inputLine in InputMongoDB.find()[start : start + int(options.linesPerThread)]:

		#### Local variable declaration ####
		global converted
		urlWithoutPoints = inputLine['requestUrl'].replace('.', '_')
		splittedTime = inputLine['date'].split('/')
		connectionDay = weekdays[(datetime.datetime(int(splittedTime[2]), int(list(calendar.month_abbr).index(splittedTime[1])), int(splittedTime[0]))).weekday()]


		#### Ending conditions ####
		if inputLine is None:
			continue

		if converted >= diffLines:
			print 'break on: ' + str(converted)
			break
		else:
			progressBarObj.update(converted)


		#### Split querystring into params ####
		if '?' in inputLine['url']:
			urlWithoutQuery = inputLine['url'].split('?')[0]
			queryString = inputLine['url'].split('?')[1].split('&')
		else:
			urlWithoutQuery = inputLine['url']
			queryString = ''
		queryString = [element.replace('.', '_') for element in queryString]


		#### Filter accessor based on uagent ####
		accessedBy = ''
		if options.bot:
			if next((True for bot in bots if inputLine['uagent'] in bot), False):
				accessedBy = True
			else:
				accessedBy = False
		else:
			accessedBy = 'Bot filtering disabled use: --bot'
		userAgent = inputLine['uagent'].replace('.', '_')


		#### Determine file extension ####
		try:
			filetype = inputLine['requestUrl'].split('.')[1].split('?')[0]
		except Exception:
			try:
				filetype = inputLine['requestUrl'].split('.')[1]
			except Exception:
				filetype = 'url'



		#### Add document on first occurance  ####
		if OutputMongoDB.find({'url': urlWithoutQuery}).count() == 0:
			OutputMongoDB.insert_one((Record_App(inputLine['method'], urlWithoutQuery)).__dict__)


		#### Batch update all metrics ####
		bulk = OutputMongoDB.initialize_unordered_bulk_op()
		bulk.find({"url": urlWithoutQuery }).update_one({'$inc': { 'totalConnections': 1 }})
		bulk.find({"url": urlWithoutQuery }).update_one({'$inc': { 'metric_day.' + connectionDay + '.counter': 1 }})
		bulk.find({"url": urlWithoutQuery }).update_one({'$inc': { 'metric_time.' + inputLine['time'] + '.counter': 1 }})
		bulk.find({"url": urlWithoutQuery }).update_one({'$inc': { 'metric_geo.' + GeoLocate(inputLine['ip']) + '.counter': 1 }})
		bulk.find({"url": urlWithoutQuery }).update_one({'$inc': { 'metric_agent.' + userAgent + '.counter': 1 }})
		bulk.find({"url": urlWithoutQuery }).update_one({'$set': { 'metric_agent.' + userAgent + '.bot': accessedBy }})
		bulk.find({"url": urlWithoutQuery }).update_one({'$inc': { 'metric_request.' + urlWithoutPoints + '.counter': 1 }})
		bulk.find({"url": urlWithoutQuery }).update_one({'$inc': { 'metric_ext.' + filetype +'.counter': 1 }})


		#### Add querystring param ####
		if len(queryString) > 0:
			for param in queryString:

				if len(param.split('=')) == 2:
					pKey = param.split('=')[0]
					pValue = param.split('=')[1]

					#### Determine type of param ####
					try:
						int(pValue)
						paramType = 'int'
					except ValueError as ve:
						paramType = 'bool' if pValue == 'true' or pValue == 'false' else 'string'
					except Exception as e:
						print param


					#### Detecting special chars in param ####
					chars = 'special' if any(char in string.punctuation for char in pValue) else 'normal'


					#### Add to bulk updates ####
					bulk.find({"url": urlWithoutQuery }).update_one({'$set': { 'metric_param.' + pKey + '.characters': chars}})
					bulk.find({"url": urlWithoutQuery }).update_one({'$set': { 'metric_param.' + pKey + '.length': len(pValue)}})
					bulk.find({"url": urlWithoutQuery }).update_one({'$set': { 'metric_param.' + pKey + '.type': paramType}})
					bulk.find({"url": urlWithoutQuery }).update_one({'$inc': { 'metric_param.' + pKey + '.' + pValue + '.counter': 1}})


		#### Execute batch ####
		try:
			bulk.execute()
		except Exception as bwe:
			pass


		#### Calculate ratio for metrics ####
		calculateRatio(urlWithoutQuery, 'metric_geo', GeoLocate(inputLine['ip']))
		calculateRatio(urlWithoutQuery, 'metric_agent', userAgent)
		calculateRatio(urlWithoutQuery, 'metric_time', inputLine['time'])
		calculateRatio(urlWithoutQuery, 'metric_day', connectionDay)
		calculateRatio(urlWithoutQuery, 'metric_ext', filetype)
		calculateRatio(urlWithoutQuery, 'metric_request', urlWithoutPoints)

		if len(queryString) > 0:
			for param in queryString:
				pass
				# calculateRatio(urlWithoutQuery, 'metric_param', param)



		#### Update progress ####
		converted += 1

	global activeWorkers
	activeWorkers -= 1

	if options.debug:
		print "[DEBUG] Worker started:"
		print "[DEBUG] Active workers: {}".format(activeWorkers)
		print "[DEBUG] Lines processed: {}".format(index)
		print '[DEBUG] Lines / seconds: {}'.format(index / ((datetime.datetime.now() - startTime).total_seconds()))


#### Prepare workload and send to worker ####
threads, progress = [], []
startRange = int(options.startIndex)
endRange = int(options.linesPerThread)
intLinesPerThread = int(options.linesPerThread)
loops = int(math.ceil(float(diffLines)/float(intLinesPerThread)))


for index in xrange(0, loops):

	#### Hold until worker is free ####
	while str(activeWorkers) == str(options.threads):
		pass

	#### Start of worker ####
	activeWorkers += 1
	t = threading.Thread(target=processLine, args=(startRange, index,))
	threads.append(t)
	t.start()

	#### Set range for next thread ####
	startRange += intLinesPerThread

#### Wait for all workers to finish ####
for thread in threads:
	thread.join()

progressBarObj.finish()





#### Print statistics ####
print("Total execution time: {} seconds".format((datetime.datetime.now() - startTime).total_seconds()))
print("Average lines per second: {} l/s".format(int(diffLines / (datetime.datetime.now() - startTime).total_seconds())))
# TODO: More statistics