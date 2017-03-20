import IP2Location
import dns.resolver
import string
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


def calculateRatio(identifier, ip, metric, mongo):
	""" Method for calculating the ratio for a given metric """

	currRecord = mongo.find_one({identifier: ip })
	for metricEntry in currRecord[metric]:
		if metricEntry is not '' or metricEntry is not None:
			mongo.update({identifier: ip}, {'$set': {metric + '.' + metricEntry + '.ratio': float(currRecord[metric][metricEntry]['counter']) / float(currRecord['general_totalConnections'])}})


def getQueryString(inputLine):
	return inputLine.split('?')[1].split('&') if '?' in inputLine else ''


def getUrlWithoutQuery(inputLine):
	return inputLine.split('?')[0] if '?' in inputLine else inputLine


def setupParser():
	parser = OptionParser()
	parser.add_option("-p", "--ping", action="store_true", dest="ping", default=True, help="Try to resolve originating domains to ip for geolocation")
	parser.add_option("-b", "--bot", action="store_true", dest="bot", default=False, help="Filter search engine bots")
	parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="Show debug messages")
	parser.add_option("-t", "--threads", action="store", dest="threads", default="1", help="Amout of threats that can be used")
	parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="5", help="Max lines per thread")
	parser.add_option("-m", "--mongo", action="store", dest="inputMongo", default="DEMO", help="Input via mongo")
	parser.add_option("-s", "--start", action="store", dest="startIndex", default="0", help="Start index for profiling")
	parser.add_option("-e", "--end", action="store", dest="endindex", default="0", help="End index for profiling")
	return parser.parse_args()




