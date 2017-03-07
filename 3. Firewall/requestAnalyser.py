import calendar
import datetime
import IP2Location
import time as t
from pymongo import MongoClient
from record import Record
from lastAdded import LastAdded

ProcessedMongo = MongoClient().Firewall.processed
StreamMongoDB = MongoClient().Firewall.TestStream
ProfileMongoDB = MongoClient().Profiles.PROFILE


weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

with open('../2. Profiler/sources/bots.txt') as f:
	bots = f.readlines()
bots = [x.strip() for x in bots]


tmpLastObj = LastAdded()
diffRatio = 0.1


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


	location = GeoLocate(request['ip'])

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
	bulk.find({"url": urlWithoutQuery }).update({'$inc': { 'metric_geo.' + location + '.counter': 1 }})
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
	calculateRatio(urlWithoutQuery, 'metric_geo', location)
	calculateRatio(urlWithoutQuery, 'metric_agent', userAgent)
	calculateRatio(urlWithoutQuery, 'metric_time', request['time'])
	calculateRatio(urlWithoutQuery, 'metric_day', connectionDay)
	calculateRatio(urlWithoutQuery, 'metric_ext', filetype)
	calculateRatio(urlWithoutQuery, 'metric_request', urlWithoutPoints)

	if len(queryString) > 0:
		for param in queryString:
			calculateRatio(urlWithoutQuery, 'metric_param', param)
			tmpLastObj.addParam(param)


	#### Create last added object ####
	tmpLastObj.location = location
	tmpLastObj.time = request['time']
	tmpLastObj.agent = userAgent
	tmpLastObj.ext = filetype
	tmpLastObj.request = urlWithoutPoints


	#### Delete packet from stream ####
	try:
		StreamMongoDB.delete_one({'_id': packet['_id']})
	except Exception as e:
		print 'Delete failed'





###########################
#### ANOMALY DETECTION ####
###########################

def startAnomalyDetection(packet):
	profileRecord = ProfileMongoDB.find_one({'url': packet['url']})
	requestRecord = ProcessedMongo.find_one({'url': packet['url']})

	anomaly_TotalConnections(profileRecord, requestRecord)
	anomaly_GeoUnknown(profileRecord, requestRecord)
	anomaly_TimeUnknown(profileRecord, requestRecord)
	anomaly_AgentUnknown(profileRecord, requestRecord)
	anomaly_ExtUnknown(profileRecord, requestRecord)
	anomaly_RequestUnknown(profileRecord, requestRecord)
	anomaly_ParamUnknown(profileRecord, requestRecord)



#################
#### UNKNOWS ####
#################

def anomaly_GeoUnknown(profileRecord, requestRecord):
	if tmpLastObj.location in profileRecord['metric_geo']:
		anomaly_GeoCounter(profileRecord, requestRecord)
		anomaly_GeoRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Unknown locations has connected ({})'.format(tmpLastObj.location)

def anomaly_TimeUnknown(profileRecord, requestRecord):
	if tmpLastObj.time in profileRecord['metric_time']:
		anomaly_TimeCounter(profileRecord, requestRecord)
		anomaly_TimeRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Connection at unfamiliar time ({})'.format(tmpLastObj.time)

def anomaly_AgentUnknown(profileRecord, requestRecord):
	if tmpLastObj.agent in profileRecord['metric_agent']:
		anomaly_AgentCounter(profileRecord, requestRecord)
		anomaly_AgentRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Connection with unfamiliar user agent ({})'.format(tmpLastObj.agent)

def anomaly_ExtUnknown(profileRecord, requestRecord):
	if tmpLastObj.ext in profileRecord['metric_ext']:
		anomaly_ExtCounter(profileRecord, requestRecord)
		anomaly_ExtRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Request for unusual file type ({})'.format(tmpLastObj.ext)

def anomaly_RequestUnknown(profileRecord, requestRecord):
	if tmpLastObj.request in profileRecord['metric_request']:
		anomaly_RequestCounter(profileRecord, requestRecord)
		anomaly_RequestRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Unfamiliar resource requested ({})'.format(tmpLastObj.request)

def anomaly_ParamUnknown(profileRecord, requestRecord):
	for param in tmpLastObj.param:
		if param in profileRecord['metric_param']:
			anomaly_ParamCounter(profileRecord, requestRecord)
		else:
			print '[ALERT] Unfamiliar resource requested ({})'.format(param)




##################
#### COUNTERS ####
##################

def anomaly_TotalConnections (profileRecord, requestRecord):
	diffRequests = int(requestRecord['totalConnections']) - int(profileRecord['totalConnections'])
	print '[ALERT] Total conncections has been exceeded ({})'.format(diffRequests) if requestRecord['totalConnections'] > profileRecord['totalConnections'] else '[OK] Total connections safe ({})'.format(diffRequests)

def anomaly_GeoCounter (profileRecord, requestRecord):
	diffGeoCounter = int(requestRecord['metric_geo'][tmpLastObj.location]['counter']) - int(profileRecord['metric_geo'][tmpLastObj.location]['counter'])
	print '[ALERT] Total connections from location has been exceeded ({} | {})'.format(diffGeoCounter, tmpLastObj.location) if requestRecord['metric_geo'][tmpLastObj.location]['counter'] > profileRecord['metric_geo'][tmpLastObj.location]['counter'] else '[OK] Connections from location safe ({} | {})'.format(diffGeoCounter, tmpLastObj.location)

def anomaly_TimeCounter (profileRecord, requestRecord):
	diffTimeCounter = int(requestRecord['metric_time'][tmpLastObj.time]['counter']) - int(profileRecord['metric_time'][tmpLastObj.time]['counter'])
	print '[ALERT] Total connections at time has been exceeded ({} | {}h)'.format(diffTimeCounter, tmpLastObj.time) if requestRecord['metric_time'][tmpLastObj.time]['counter'] > profileRecord['metric_time'][tmpLastObj.time]['counter'] else '[OK] Connections at time safe ({} | {}h)'.format(diffTimeCounter, tmpLastObj.time)

def anomaly_AgentCounter (profileRecord, requestRecord):
	diffAgentCounter = int(requestRecord['metric_agent'][tmpLastObj.agent]['counter']) - int(profileRecord['metric_agent'][tmpLastObj.agent]['counter'])
	print '[ALERT] Total connections from user agent has been exceeded ({} | {})'.format(diffAgentCounter, tmpLastObj.agent) if requestRecord['metric_agent'][tmpLastObj.agent]['counter'] > profileRecord['metric_agent'][tmpLastObj.agent]['counter'] else '[OK] Connections from user agent safe ({} | {}h)'.format(diffAgentCounter, tmpLastObj.agent)

def anomaly_ExtCounter (profileRecord, requestRecord):
	diffExtCounter = int(requestRecord['metric_ext'][tmpLastObj.ext]['counter']) - int(profileRecord['metric_ext'][tmpLastObj.ext]['counter'])
	print '[ALERT] Total requests for filetype has been exceeded ({} | {})'.format(diffExtCounter, tmpLastObj.ext) if requestRecord['metric_ext'][tmpLastObj.ext]['counter'] > profileRecord['metric_ext'][tmpLastObj.ext]['counter'] else '[OK] Connections for filetype safe ({} | {})'.format(diffExtCounter, tmpLastObj.ext)

def anomaly_RequestCounter (profileRecord, requestRecord):
	diffRequestCounter = int(requestRecord['metric_request'][tmpLastObj.request]['counter']) - int(profileRecord['metric_request'][tmpLastObj.request]['counter'])
	print '[ALERT] Total requests for resource has been exceeded ({} | {})'.format(diffRequestCounter, tmpLastObj.request) if requestRecord['metric_request'][tmpLastObj.request]['counter'] > profileRecord['metric_request'][tmpLastObj.request]['counter'] else '[OK] Requests for resource safe ({} | {})'.format(diffRequestCounter, tmpLastObj.request)

def anomaly_ParamCounter (profileRecord, requestRecord):
	for param in tmpLastObj.param:
		diffParamCounter = int(requestRecord['metric_param'][param]['counter']) - int(profileRecord['metric_param'][param]['counter'])
		print '[ALERT] Total requests with parameter has been exceeded ({} | {})'.format(diffParamCounter, param) if requestRecord['metric_param'][param]['counter'] > profileRecord['metric_param'][param]['counter'] else '[OK] Connections with parameter safe ({} | {})'.format(diffParamCounter, param)



################
#### RATIOS ####
################

def anomaly_GeoRatio(profileRecord, requestRecord):
	diffGeoRatio = float(requestRecord['metric_geo'][tmpLastObj.location]['ratio']) - float(profileRecord['metric_geo'][tmpLastObj.location]['ratio'])
	print '[OK] Ratio geolocation safe ({} | {})'.format(diffGeoRatio, tmpLastObj.location) if -diffRatio <= diffGeoRatio <= diffRatio else '[ALERT] Ratio geolocation has been exceeded ({} | {})'.format(diffGeoRatio, tmpLastObj.location)

def anomaly_TimeRatio(profileRecord, requestRecord):
	diffTimeRatio = float(requestRecord['metric_time'][tmpLastObj.time]['ratio']) - float(profileRecord['metric_time'][tmpLastObj.time]['ratio'])
	print '[OK] Ratio time safe ({} | {}h)'.format(diffTimeRatio, tmpLastObj.time) if -diffRatio <= diffTimeRatio <= diffRatio else '[ALERT] Ratio time has been exceeded ({} | {}h)'.format(diffTimeRatio, tmpLastObj.time)

def anomaly_AgentRatio(profileRecord, requestRecord):
	diffAgentRatio = float(requestRecord['metric_agent'][tmpLastObj.agent]['ratio']) - float(profileRecord['metric_agent'][tmpLastObj.agent]['ratio'])
	print '[OK] Ratio user agent safe ({} | {})'.format(diffAgentRatio, tmpLastObj.agent) if -diffRatio <= diffAgentRatio <= diffRatio else '[ALERT] Ratio user agent has been exceeded ({} | {})'.format(diffAgentRatio, tmpLastObj.agent)

def anomaly_ExtRatio(profileRecord, requestRecord):
	diffExtRatio = float(requestRecord['metric_ext'][tmpLastObj.ext]['ratio']) - float(profileRecord['metric_ext'][tmpLastObj.ext]['ratio'])
	print '[OK] Ratio file extension safe ({} | {})'.format(diffExtRatio, tmpLastObj.ext) if -diffRatio <= diffExtRatio <= diffRatio else '[ALERT] Ratio file extension has been exceeded ({} | {})'.format(diffExtRatio, tmpLastObj.ext)

def anomaly_RequestRatio(profileRecord, requestRecord):
	diffRequestRatio = float(requestRecord['metric_request'][tmpLastObj.request]['ratio']) - float(profileRecord['metric_request'][tmpLastObj.request]['ratio'])
	print '[OK] Ratio resource requests safe ({} | {})'.format(diffRequestRatio, tmpLastObj.request) if -diffRatio <= diffRequestRatio <= diffRatio else '[ALERT] Ratio resource requests has been exceeded ({} | {})'.format(diffRequestRatio, tmpLastObj.request)


##############
#### MAIN ####
##############

if __name__ == '__main__':
	print 'Waiting for packet...'
	while True:
		for packet in StreamMongoDB.find():
			print 'Started processing'

			processRequest(packet)
			startAnomalyDetection(packet)

			print '-----------------'