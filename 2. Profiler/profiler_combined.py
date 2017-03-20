import progressbar
import string
import datetime
import threading
import math
import IP2Location
import dns.resolver

from collections import OrderedDict
from pymongo import MongoClient
from optparse import OptionParser
from record_user import Record_User
from record_app import Record_App


#### Init global vars ####
initTime = str('%02d' % datetime.datetime.now().hour) + ":" +  str('%02d' % datetime.datetime.now().minute) + ":" +  str('%02d' % datetime.datetime.now().second)
startTime = datetime.datetime.now()
converted, activeWorkers = 0, 0


#### Init options ####
parser = OptionParser()
parser.add_option("-p", "--ping", action="store_true", dest="ping", default=False, help="Try to resolve originating domains to ip for geolocation")
parser.add_option("-b", "--bot", action="store_true", dest="bot", default=False, help="Filter search engine bots")
parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="Show debug messages")
parser.add_option("-t", "--threads", action="store", dest="threads", default="1", help="Amout of threats that can be used")
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="5", help="Max lines per thread")
parser.add_option("-m", "--mongo", action="store", dest="inputMongo", default="DEMO", help="Input via mongo")
parser.add_option("-s", "--start", action="store", dest="startIndex", default="0", help="Start index for profiling")
parser.add_option("-e", "--end", action="store", dest="endindex", default="0", help="End index for profiling")
options, args = parser.parse_args()


#### Init DB ####
OutputMongoDB = MongoClient().profile_combined['profile_combined_' + initTime]
InputMongoDB = MongoClient().FormattedLogs[options.inputMongo]
BotMongoDB = MongoClient().config_static.profile_bots


#### Determening lines to process####
options.endindex = InputMongoDB.count() if int(options.endindex) == 0 else int(options.endindex)
diffLines = int(options.endindex) - int(options.startIndex) + 1


#### Preparing progress bar ####
progressBarObj = progressbar.ProgressBar(maxval=diffLines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
progressBarObj.start()




##########################
#### Helper functions ####
##########################


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


def calculateRatio(ip, metric):
	""" Method for calculating the ratio for a given metric """

	currRecord = OutputMongoDB.find_one({'general_ip': ip })

	#### Update ratio on all affected records and metrics (if counter changes on one metric, ratio on all has to be updated) ####
	for metricEntry in currRecord[metric]:
		if metricEntry is not '' or metricEntry is not None:
			OutputMongoDB.update({'general_ip': ip}, {'$set': {metric + '.' + metricEntry + '.ratio': float(currRecord[metric][metricEntry]['counter']) / float(currRecord['general_totalConnections'])}})


def calculateRatioParam(url, pKey):
	""" Method for calculating the ratio for a given metric """

	currRecord = OutputMongoDB.find_one({'url': url })

	for param in currRecord['metric_param'][pKey]:
		try:
			#### Update ratio on all affected records and metrics (if counter changes on one metric, ratio on all has to be updated) ####
			OutputMongoDB.update({'url': url}, {'$set': { 'metric_param' + '.' + pKey + '.' + param + '.ratio': float(currRecord['metric_param'][pKey][param]['counter']) / float(currRecord['metric_param'][pKey]['counter'])}})
		except TypeError:
			#### Not every metric has a counter/ratio field, this will be catched by the TypeError exception ####
			pass




########################
#### Main functions ####
########################

def processLine(start, index):
	""" Assign workers with workload """

	#### Ending conditions ####
	global converted

	for inputLine in InputMongoDB.find()[start : start + int(options.linesPerThread)]:
		if inputLine is None:
			continue

		if converted >= diffLines:
			print 'break on: ' + str(converted)
			break
		else:
			progressBarObj.update(converted)

		#### Init local vars ####
		if '?' in inputLine['url']:
			urlWithoutQuery = inputLine['url'].split('?')[0]
			queryString = inputLine['url'].split('?')[1].split('&')
		else:
			urlWithoutQuery = inputLine['url']
			queryString = ''

		timestamp = datetime.datetime.strptime(inputLine['fulltime'].split(' ')[0], '%d/%b/%Y:%H:%M:%S')
		userAgent_Replaced = inputLine['uagent'].replace('.', '_')
		requestUrl_Replaced = inputLine['requestUrl'].replace('.', '_')
		urlWithoutQuery = urlWithoutQuery.replace('.', '_')
		queryString = [element.replace('.', '_') for element in queryString]


		#### Insert record if it doesn't exists ####
		if OutputMongoDB.find({'identifier': inputLine['ip']}).count() == 0:
			OutputMongoDB.insert_one({'identifier': inputLine['ip'], 'general_location': GeoLocate(inputLine['ip'])})

		#### Add document on first occurance  ####
		elif OutputMongoDB.find({'identifier': urlWithoutQuery}).count() == 0:
			OutputMongoDB.insert_one({'identifier' : urlWithoutQuery})


	global activeWorkers
	activeWorkers -= 1








###########################
#### Worker Assignment ####
###########################


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