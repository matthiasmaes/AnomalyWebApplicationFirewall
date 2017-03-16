import calendar
import datetime, IP2Location
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

threshold_ratio = 0.1
threshold_counter = 5



#################
#### HELPERS ####
#################

def GeoLocate(ip):
	""" Method for translating ip-address to geolocation (country) """
	try:
		IP2LocObj = IP2Location.IP2Location();
		IP2LocObj.open('../2. Profiler/sources/IP2GEODB.BIN');
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

	#### REFACTORED SOME THINGS CHECK LATER IF STILL WORKS!!!
	try:
		StreamMongoDB.delete_one({'_id': request['_id']})
	except Exception:
		print 'Delete failed'





###########################
#### ANOMALY DETECTION ####
###########################

def startAnomalyDetection(packet):
	""" Start anomaly detection process """

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
	""" Detect unknowns in geo metric """

	if tmpLastObj.location in profileRecord['metric_geo']:
		anomaly_GeoCounter(profileRecord, requestRecord)
		anomaly_GeoRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Unknown locations has connected ({})'.format(tmpLastObj.location)


def anomaly_TimeUnknown(profileRecord, requestRecord):
	""" Detect unknowns in time metric """

	if tmpLastObj.time in profileRecord['metric_time']:
		anomaly_TimeCounter(profileRecord, requestRecord)
		anomaly_TimeRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Connection at unfamiliar time ({})'.format(tmpLastObj.time)


def anomaly_AgentUnknown(profileRecord, requestRecord):
	""" Detect unknowns in agent metric """

	if tmpLastObj.agent in profileRecord['metric_agent']:
		anomaly_AgentCounter(profileRecord, requestRecord)
		anomaly_AgentRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Connection with unfamiliar user agent ({})'.format(tmpLastObj.agent)


def anomaly_ExtUnknown(profileRecord, requestRecord):
	""" Detect unknowns in file extension metric """

	if tmpLastObj.ext in profileRecord['metric_ext']:
		anomaly_ExtCounter(profileRecord, requestRecord)
		anomaly_ExtRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Request for unusual file type ({})'.format(tmpLastObj.ext)


def anomaly_RequestUnknown(profileRecord, requestRecord):
	""" Detect unknowns in request metric """

	if tmpLastObj.request in profileRecord['metric_request']:
		anomaly_RequestCounter(profileRecord, requestRecord)
		anomaly_RequestRatio(profileRecord, requestRecord)
	else:
		print '[ALERT] Unfamiliar resource requested ({})'.format(tmpLastObj.request)


def anomaly_ParamUnknown(profileRecord, requestRecord):
	""" Detect unknowns in parameter metric """

	for param in tmpLastObj.param:
		if param in profileRecord['metric_param']:
			anomaly_ParamCounter(profileRecord, requestRecord)
			anomaly_ParamRatio(profileRecord, requestRecord)
		else:
			print '[ALERT] Unfamiliar resource requested ({})'.format(param)




##################
#### COUNTERS ####
##################

def anomaly_TotalConnections (profileRecord, requestRecord):
	""" Detect to many connections """
	diff = int(requestRecord['totalConnections']) - int(profileRecord['totalConnections'])
	print '[ALERT] Total conncections has been exceeded ({})'.format(diff) if threshold_counter < diff else '[OK] Total connections safe ({})'.format(diff)

def anomaly_GeoCounter (profileRecord, requestRecord):
	""" Detect to many connections from specific country """
	diff = int(requestRecord['metric_geo'][tmpLastObj.location]['counter']) - int(profileRecord['metric_geo'][tmpLastObj.location]['counter'])
	print '[ALERT] Total connections from location has been exceeded ({} | {})'.format(diff, tmpLastObj.location) if threshold_counter < diff else '[OK] Connections from location safe ({} | {})'.format(diff, tmpLastObj.location)

def anomaly_TimeCounter (profileRecord, requestRecord):
	""" Detect to many connections at specific time """
	diff = int(requestRecord['metric_time'][tmpLastObj.time]['counter']) - int(profileRecord['metric_time'][tmpLastObj.time]['counter'])
	print '[ALERT] Total connections at time has been exceeded ({} | {}h)'.format(diff, tmpLastObj.time) if threshold_counter < diff else '[OK] Connections at time safe ({} | {}h)'.format(diff, tmpLastObj.time)

def anomaly_AgentCounter (profileRecord, requestRecord):
	""" Detect to many connections with specific agent """
	diff = int(requestRecord['metric_agent'][tmpLastObj.agent]['counter']) - int(profileRecord['metric_agent'][tmpLastObj.agent]['counter'])
	print '[ALERT] Total connections from user agent has been exceeded ({} | {})'.format(diff, tmpLastObj.agent) if threshold_counter < diff else '[OK] Connections from user agent safe ({} | {}h)'.format(diff, tmpLastObj.agent)

def anomaly_ExtCounter (profileRecord, requestRecord):
	""" Detect to many connections to specific file types """
	diff = int(requestRecord['metric_ext'][tmpLastObj.ext]['counter']) - int(profileRecord['metric_ext'][tmpLastObj.ext]['counter'])
	print '[ALERT] Total requests for filetype has been exceeded ({} | {})'.format(diff, tmpLastObj.ext) if threshold_counter < diff else '[OK] Connections for filetype safe ({} | {})'.format(diff, tmpLastObj.ext)

def anomaly_RequestCounter (profileRecord, requestRecord):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_request'][tmpLastObj.request]['counter']) - int(profileRecord['metric_request'][tmpLastObj.request]['counter'])
	print '[ALERT] Total requests for resource has been exceeded ({} | {})'.format(diff, tmpLastObj.request) if threshold_counter < diff else '[OK] Requests for resource safe ({} | {})'.format(diff, tmpLastObj.request)

def anomaly_StatusCounter (profileRecord, requestRecord):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_status'][tmpLastObj.request]['counter']) - int(profileRecord['metric_status'][tmpLastObj.request]['counter'])
	print '[ALERT] More status than usual ({} | {})'.format(diff, tmpLastObj.request) if threshold_counter < diff else '[OK] Status for resource safe ({} | {})'.format(diff, tmpLastObj.request)

def anomaly_MethodCounter (profileRecord, requestRecord):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_method'][tmpLastObj.request]['counter']) - int(profileRecord['metric_method'][tmpLastObj.request]['counter'])
	print '[ALERT] More methods than usual ({} | {})'.format(diff, tmpLastObj.request) if threshold_counter < diff else '[OK] Methods for resource safe ({} | {})'.format(diff, tmpLastObj.request)

def anomaly_ParamCounter (profileRecord, requestRecord):
	""" Detect to many connections on specific querystring parameter """
	for param in tmpLastObj.param:
		diff = int(requestRecord['metric_param'][param]['counter']) - int(profileRecord['metric_param'][param]['counter'])
		print '[ALERT] Total requests with parameter has been exceeded ({} | {})'.format(diff, param) if threshold_counter < diff else '[OK] Connections with parameter safe ({} | {})'.format(diff, param)



################
#### RATIOS ####
################

def anomaly_GeoRatio(profileRecord, requestRecord):
	""" Detect divergent geolocation ratio """
	diff = float(requestRecord['metric_geo'][tmpLastObj.location]['ratio']) - float(profileRecord['metric_geo'][tmpLastObj.location]['ratio'])
	print '[OK] Ratio geolocation safe ({} | {})'.format(diff, tmpLastObj.location) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio geolocation has been exceeded ({} | {})'.format(diff, tmpLastObj.location)


def anomaly_TimeRatio(profileRecord, requestRecord):
	""" Detect divergent time ratio """
	diff = float(requestRecord['metric_time'][tmpLastObj.time]['ratio']) - float(profileRecord['metric_time'][tmpLastObj.time]['ratio'])
	print '[OK] Ratio time safe ({} | {}h)'.format(diff, tmpLastObj.time) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio time has been exceeded ({} | {}h)'.format(diff, tmpLastObj.time)


def anomaly_AgentRatio(profileRecord, requestRecord):
	""" Detect divergent agent ratio """
	diff = float(requestRecord['metric_agent'][tmpLastObj.agent]['ratio']) - float(profileRecord['metric_agent'][tmpLastObj.agent]['ratio'])
	print '[OK] Ratio user agent safe ({} | {})'.format(diff, tmpLastObj.agent) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio user agent has been exceeded ({} | {})'.format(diff, tmpLastObj.agent)


def anomaly_ExtRatio(profileRecord, requestRecord):
	""" Detect divergent file type ratio """
	diff = float(requestRecord['metric_ext'][tmpLastObj.ext]['ratio']) - float(profileRecord['metric_ext'][tmpLastObj.ext]['ratio'])
	print '[OK] Ratio file extension safe ({} | {})'.format(diff, tmpLastObj.ext) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio file extension has been exceeded ({} | {})'.format(diff, tmpLastObj.ext)


def anomaly_RequestRatio(profileRecord, requestRecord):
	""" Detect divergent request ratio """
	diff = float(requestRecord['metric_request'][tmpLastObj.request]['ratio']) - float(profileRecord['metric_request'][tmpLastObj.request]['ratio'])
	print '[OK] Ratio resource requests safe ({} | {})'.format(diff, tmpLastObj.request) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio resource requests has been exceeded ({} | {})'.format(diff, tmpLastObj.request)


def anomaly_StatusRatio(profileRecord, requestRecord):
	""" Detect divergent request ratio """
	diff = float(requestRecord['metric_status'][tmpLastObj.request]['ratio']) - float(profileRecord['metric_status'][tmpLastObj.request]['ratio'])
	print '[OK] Ratio status safe ({} | {})'.format(diff, tmpLastObj.request) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio status has been exceeded ({} | {})'.format(diff, tmpLastObj.request)


def anomaly_MethodRatio(profileRecord, requestRecord):
	""" Detect divergent request ratio """
	diff = float(requestRecord['metric_method'][tmpLastObj.request]['ratio']) - float(profileRecord['metric_method'][tmpLastObj.request]['ratio'])
	print '[OK] Ratio method safe ({} | {})'.format(diff, tmpLastObj.request) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio method has been exceeded ({} | {})'.format(diff, tmpLastObj.request)


def anomaly_ParamRatio(profileRecord, requestRecord):
	""" Detect divergent param ratio """
	for param in tmpLastObj.param:
		diff = float(requestRecord['metric_param'][param]['ratio']) - float(profileRecord['metric_param'][param]['ratio'])
		print '[OK] Ratio resource requests safe ({} | {})'.format(diff, param) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio resource requests has been exceeded ({} | {})'.format(diff, param)


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