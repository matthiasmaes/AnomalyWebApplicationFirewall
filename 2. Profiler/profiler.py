# Public classes
import progressbar
import datetime
import threading
import calendar
import math
import IP2Location
import dns.resolver
from pymongo import MongoClient
from optparse import OptionParser

from record import Record


#### Init global vars ####
initTime = str(datetime.datetime.now().hour) + "_" +  str(datetime.datetime.now().minute) + "_" +  str(datetime.datetime.now().second)
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
OutputMongoDB = MongoClient().Profiles[initTime + '_Profile']
InputMongoDB = MongoClient().FormattedLogs[options.inputMongo]


OutputMongoDB.create_index('url', background=True)

#### Determening lines ####
options.endindex = InputMongoDB.count() if int(options.endindex) == 0 else int(options.endindex)

diffLines = int(options.endindex) - int(options.startIndex) + 1

print diffLines

#### Reading bot file ####
if options.bot:
	with open('sources/bots.txt') as f:
		bots = f.readlines()
	bots = [x.strip() for x in bots]


#### Preparing progress bar ####
progressBarObj = progressbar.ProgressBar(maxval=diffLines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
progressBarObj.start()



def GeoLocate(ip):
	try:
		IP2LocObj = IP2Location.IP2Location();
		IP2LocObj.open("sources\IP2GEODB.BIN");
		return IP2LocObj.get_all(ip).country_long;
	except Exception:
		if ping:
			try:
				return IP2LocObj.get_all(dns.resolver.query(ip, 'A')[0]).country_long;
			except Exception:
				return "Geolocation failed"
		else:
			return "Domain translation disabled"



def calculateRatio(url, metric, data):

	currRecord = OutputMongoDB.find_one({"url": url })

	OutputMongoDB.update({'url': url}, {'$set': { metric + '.' + data + '.ratio': float(currRecord[metric][data]['counter']) / float(currRecord['totalConnections'])}})

	for metricEntry in currRecord[metric]:
		OutputMongoDB.update({'url': url}, {'$set': {metric + '.' + metricEntry + '.ratio': float(currRecord[metric][metricEntry]['counter']) / float(currRecord['totalConnections'])}})






def processLine(start, index):
	""" Assign workers with workload """

	for record in InputMongoDB.find()[start : start + int(options.linesPerThread)]:

		global converted

		#### Get record based on index ####
		inputLine = record

		urlWithoutPoints = inputLine['requestUrl'].replace('.', '_')

		#### Break loop if index is not found ####
		if inputLine is None: 
			continue	

		#### End if all lines were converted ####
		if converted >= diffLines:
			print 'break on: ' + str(converted)
			break
		else:
			progressBarObj.update(converted)

		#### Format time ####
		splittedTime = inputLine['date'].split('/')
		connectionDay = weekdays[(datetime.datetime(int(splittedTime[2]), int(list(calendar.month_abbr).index(splittedTime[1])), int(splittedTime[0]))).weekday()]


		if '?' in inputLine['url']:
			urlWithoutQuery = inputLine['url'].split('?')[0]
			queryString = inputLine['url'].split('?')[1].split('&')
		else:
			urlWithoutQuery = inputLine['url']
			queryString = ''
		queryString = [element.replace('.', '_') for element in queryString]


		#### Add document on first occurance  ####
		if OutputMongoDB.find({'url': urlWithoutQuery}).count() == 0:
			OutputMongoDB.insert_one((Record(inputLine['method'], urlWithoutQuery, inputLine['code'], inputLine['size'])).__dict__)		

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


		#### Init Batch ####
		bulk = OutputMongoDB.initialize_unordered_bulk_op()
	
		#### Add accessDay from connection ####
		bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_day.' + connectionDay + '.counter': 1 }})

		#### Add time from connection ####
		bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_time.' + inputLine['time'] + '.counter': 1 }})

		#### Add location from connection ####
		bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_geo.' + GeoLocate(inputLine['ip']) + '.counter': 1 }})

		#### Add access agent ####
		bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_agent.' + userAgent + '.counter': 1 }})
		bulk.find({"url": urlWithoutQuery }).update({'$set': { 'metric_agent.' + userAgent + '.bot': accessedBy }})


		#### Add request url ####
		bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_request.' + urlWithoutPoints + '.counter': 1 }})

		#### update total amount of connections ####
		bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'totalConnections': 1 }})



		#### Add querystring param ####
		if len(queryString) > 0:	
			for param in queryString:
				bulk.find({"url": urlWithoutQuery }).update({'$inc': {'metric_param.' + param + '.counter': 1}})


		#### Add ratio filetype ####
		try:
			filetype = inputLine['requestUrl'].split('.')[1].split('?')[0]			
		except Exception:
			try:
				filetype = inputLine['requestUrl'].split('.')[1]
			except Exception:
				filetype = 'url'


		bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_ext.' + filetype +'.counter': 1 }})



		#### Execute batch ####
		try:
			bulk.execute()
		except Exception as bwe:
			print(bwe.details)




		calculateRatio(urlWithoutQuery, 'metric_geo', GeoLocate(inputLine['ip']))
		calculateRatio(urlWithoutQuery, 'metric_agent', userAgent)
		calculateRatio(urlWithoutQuery, 'metric_time', inputLine['time'])
		calculateRatio(urlWithoutQuery, 'metric_day', connectionDay)
		calculateRatio(urlWithoutQuery, 'metric_ext', filetype)
		calculateRatio(urlWithoutQuery, 'metric_request', urlWithoutPoints)

		if len(queryString) > 0:	
			for param in queryString:
				calculateRatio(urlWithoutQuery, 'metric_param', param)


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