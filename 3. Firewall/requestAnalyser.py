import calendar
import datetime
import IP2Location
import time as t
from pymongo import MongoClient
from record import Record

ProcessedMongo = MongoClient().Firewall.processed
StreamMongoDB = MongoClient().Firewall.TestStream
ProfileMongoDB = MongoClient().Profiles.PROFILE


weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

with open('../2. Profiler/sources/bots.txt') as f:
	bots = f.readlines()
bots = [x.strip() for x in bots]




def GeoLocate(ip):
	""" Method for translating ip-address to geolocation (country) """

	try:
		IP2LocObj = IP2Location.IP2Location();
		IP2LocObj.open('../2. Profiler/sources\IP2GEODB.BIN');
		return IP2LocObj.get_all(ip).country_long;
	except Exception as e:
		print e
		return 'Geolocation failed'



def calculateRatio(url, metric, data):
	""" Method for calculating the ratio for a given metric """

	currRecord = ProcessedMongo.find_one({"url": url })
	ProcessedMongo.update({'url': url}, {'$set': { metric + '.' + data + '.ratio': float(currRecord[metric][data]['counter']) / float(currRecord['totalConnections'])}})
	for metricEntry in currRecord[metric]:
		ProcessedMongo.update({'url': url}, {'$set': {metric + '.' + metricEntry + '.ratio': float(currRecord[metric][metricEntry]['counter']) / float(currRecord['totalConnections'])}})



def processRequest(request):
	#### Local variable declaration ####
	urlWithoutPoints = request['requestUrl'].replace('.', '_')
	splittedTime = request['date'].split('/')
	connectionDay = weekdays[(datetime.datetime(int(splittedTime[2]), int(list(calendar.month_abbr).index(splittedTime[1])), int(splittedTime[0]))).weekday()]


	#### Ending conditions ####
	if request is None:
		return

	#### Split querystring into params ####
	if '?' in request['url']:
		urlWithoutQuery = request['url'].split('?')[0]
		queryString = request['url'].split('?')[1].split('&')
	else:
		urlWithoutQuery = request['url']
		queryString = ''
	queryString = [element.replace('.', '_') for element in queryString]


	#### Filter accessor based on uagent ####
	if next((True for bot in bots if request['uagent'] in bot), False):
		accessedBy = True
	else:
		accessedBy = False

	userAgent = request['uagent'].replace('.', '_')


	#### Determine file extension ####
	try:
		filetype = request['requestUrl'].split('.')[1].split('?')[0]
	except Exception:
		try:
			filetype = request['requestUrl'].split('.')[1]
		except Exception:
			filetype = 'url'


	#### Add document on first occurance  ####
	if ProcessedMongo.find({'url': urlWithoutQuery}).count() == 0:
		ProcessedMongo.insert_one((Record(request['method'], urlWithoutQuery)).__dict__)


	#### Batch update all metrics ####
	bulk = ProcessedMongo.initialize_unordered_bulk_op()
	bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'totalConnections': 1 }})
	bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_day.' + connectionDay + '.counter': 1 }})
	bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_time.' + request['time'] + '.counter': 1 }})
	bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_geo.' + GeoLocate(request['ip']) + '.counter': 1 }})
	bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_agent.' + userAgent + '.counter': 1 }})
	bulk.find({"url": urlWithoutQuery }).update({'$set': { 'metric_agent.' + userAgent + '.bot': accessedBy }})
	bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_request.' + urlWithoutPoints + '.counter': 1 }})
	bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_ext.' + filetype +'.counter': 1 }})


	#### Add querystring param ####
	if len(queryString) > 0:
		for param in queryString:
			bulk.find({"url": urlWithoutQuery }).update({'$inc': {'metric_param.' + param + '.counter': 1}})


	#### Execute batch ####
	try:
		bulk.execute()
	except Exception as bwe:
		print(bwe.details)

	#### Calculate ratio for metrics ####
	calculateRatio(urlWithoutQuery, 'metric_geo', GeoLocate(request['ip']))
	calculateRatio(urlWithoutQuery, 'metric_agent', userAgent)
	calculateRatio(urlWithoutQuery, 'metric_time', request['time'])
	calculateRatio(urlWithoutQuery, 'metric_day', connectionDay)
	calculateRatio(urlWithoutQuery, 'metric_ext', filetype)
	calculateRatio(urlWithoutQuery, 'metric_request', urlWithoutPoints)

	if len(queryString) > 0:
		for param in queryString:
			calculateRatio(urlWithoutQuery, 'metric_param', param)

	StreamMongoDB.delete_one({'_id': packet['_id']})


def startAnomalyDetection(packet):
	profileRecord = ProfileMongoDB.find_one({'url': packet['url']})
	requestRecord = ProcessedMongo.find_one({'url': packet['url']})

	anomaly_TotalConnections(profileRecord, requestRecord)


def anomaly_TotalConnections(profileRecord, requestRecord):
	diffRequests = int(requestRecord['totalConnections']) - int(profileRecord['totalConnections'])
	print '[ALERT] Total conncections has been exceeded ({})'.format(diffRequests) if requestRecord['totalConnections'] > profileRecord['totalConnections'] else '[OK] Total connections safe ({})'.format(diffRequests)





if __name__ == '__main__':
	while True:
		for packet in StreamMongoDB.find():
			print 'Started processing'
			processRequest(packet)
			startAnomalyDetection(packet)

		print 'Waiting for packet...'
		t.sleep(1)
