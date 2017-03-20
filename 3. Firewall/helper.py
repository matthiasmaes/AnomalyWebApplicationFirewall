import IP2Location
import dns.resolver
import string
import datetime

from collections import OrderedDict
from optparse import OptionParser


def GeoLocate(ip, ping):
	""" Method for translating ip-address to geolocation (country) """

	try:
		IP2LocObj = IP2Location.IP2Location();
		IP2LocObj.open("sources\IP2GEODB.BIN");
		return IP2LocObj.get_all(ip).country_long;
	except Exception as e:
		print e
		if ping:
			try:
				return IP2LocObj.get_all(dns.resolver.query(ip, 'A')[0]).country_long;
			except Exception:
				return "Geolocation failed"
		else:
			return "Domain translation disabled"


def calculateRatio(identifier, value, metric, mongo):
	""" Method for calculating the ratio for a given metric """

	currRecord = mongo.find_one({identifier: value })
	for metricEntry in currRecord[metric]:
		if metricEntry is not '' or metricEntry is not None:
			mongo.update({identifier: value}, {'$set': {metric + '.' + metricEntry + '.ratio': float(currRecord[metric][metricEntry]['counter']) / float(currRecord['general_totalConnections'])}})


def calculateRatioParam(identifier, value, pKey, mongo):
	""" Method for calculating the ratio for a given metric """

	currRecord = mongo.find_one({identifier: value })
	for param in currRecord['metric_param'][pKey]:
		try:
			#### Update ratio on all affected records and metrics (if counter changes on one metric, ratio on all has to be updated) ####
			mongo.update({identifier: value}, {'$set': { 'metric_param' + '.' + pKey + '.' + param + '.ratio': float(currRecord['metric_param'][pKey][param]['counter']) / float(currRecord['metric_param'][pKey]['counter'])}})
		except TypeError:
			#### Not every metric has a counter/ratio field, this will be catched by the TypeError exception ####
			pass

def getQueryString(inputLine):
	return inputLine.split('?')[1].split('&') if '?' in str(inputLine) else ''


def getUrlWithoutQuery(inputLine):
	return inputLine.split('?')[0] if '?' in str(inputLine) else inputLine


def getFileType(inputLine):
	try:
		filetype = inputLine.split('.')[1].split('?')[0]
	except Exception:
		try:
			filetype = inputLine.split('.')[1]
		except Exception:
			filetype = 'url'
	return filetype


def makeTimeline(mongo, inputLine, value):
	print inputLine
	print value
	timelineDict = mongo.find_one({'_id' : inputLine})['general_timeline']
	timelineList = map(list, OrderedDict(sorted(timelineDict.items(), key=lambda t: datetime.datetime.strptime(t[0], '%d/%b/%Y %H:%M:%S'))).items())

	for event in timelineList:
		#### Calculate avg time spent for each base url ####
		if timelineList.index(event) == len(timelineList) - 1:
			break

		time1 = datetime.datetime.strptime(event[0], '%d/%b/%Y %H:%M:%S')
		time2 = datetime.datetime.strptime(timelineList[timelineList.index(event)+1][0], '%d/%b/%Y %H:%M:%S')

		delta = time2 - time1

		if delta.total_seconds() > 5 and delta.total_seconds() < 3600:
			counter = mongo.find_one({ '_id' : inputLine })['metric_conn'][value]['counter']
			try:
				orgAvg = mongo.find_one({ '_id' : inputLine })['metric_timespent'][value]
				newAvg = orgAvg + ((delta.total_seconds() - orgAvg) / counter)
			except KeyError:
				newAvg = delta.total_seconds()
			finally:
				mongo.update_one({ '_id' : inputLine }, { '$set' : {'metric_timespent.' + value : int(newAvg)}})


def setupParser():
	parser = OptionParser()
	parser.add_option("-p", "--ping", action="store_true", dest="ping", default=True, help="Try to resolve originating domains to ip for geolocation")
	parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="Show debug messages")
	parser.add_option("-t", "--threads", action="store", dest="threads", default="1", help="Amout of threats that can be used")
	parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="5", help="Max lines per thread")
	parser.add_option("-m", "--mongo", action="store", dest="inputMongo", default="DEMO", help="Input via mongo")
	parser.add_option("-s", "--start", action="store", dest="startIndex", default="0", help="Start index for profiling")
	parser.add_option("-e", "--end", action="store", dest="endindex", default="0", help="End index for profiling")
	return parser.parse_args()