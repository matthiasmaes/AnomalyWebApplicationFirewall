import calendar
import helper
import datetime
from pymongo import MongoClient
from record import Record

ProcessedMongo = MongoClient().Firewall.processed
StreamMongoDB = MongoClient().Firewall.TestStream
ProfileAppMongoDB = MongoClient().profile_app['profile_app_11:35:52']
ProfileUserMongoDB = MongoClient().profile_user.test

IPReputationMongoDB = MongoClient().config_static.firewall_blocklist
BotMongoDB = MongoClient().config_static.profile_bots

threshold_ratio = 0.1
threshold_counter = 5

#################
#### HELPERS ####
#################

def processRequest(inputRequest, keyValue, otherkeyValue):
	""" Assign workers with workload """

	global activeWorkers

	#### Ending conditions ####
	if inputRequest is None:
		return

	timestamp = datetime.datetime.strptime(inputRequest['fulltime'].split(' ')[0], '%d/%b/%Y:%H:%M:%S')
	urlWithoutQuery = helper.getUrlWithoutQuery(inputRequest['url'])
	queryString = [element.replace('.', '_') for element in helper.getQueryString(inputRequest['url'])]


	#### Add document on first occurance  ####
	if ProcessedMongo.find({'_id': keyValue}).count() == 0:
		ProcessedMongo.insert_one({'_id': keyValue})


	#### Batch update all metrics ####
	bulk = ProcessedMongo.initialize_ordered_bulk_op()
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'general_totalConnections': 1 }})
	bulk.find({'_id': keyValue }).update_one({'$set': { 'general_timeline.' + timestamp.strftime('%d/%b/%Y %H:%M:%S'): otherkeyValue}})
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_day.' + timestamp.strftime("%A") + '.counter': 1 }})
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_time.' + timestamp.strftime("%H") + '.counter': 1 }})
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_agent.' + inputRequest['uagent'].replace('.', '_') + '.counter': 1 }})
	bulk.find({'_id': keyValue }).update_one({'$set': { 'metric_agent.' + inputRequest['uagent'].replace('.', '_') + '.uagentType': 'Human' if BotMongoDB.find({'agent': inputRequest['uagent']}).count() == 0 else 'Bot' }})
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_request.' + inputRequest['requestUrl'].replace('.', '_') + '.counter': 1 }})
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_ext.' + helper.getFileType(inputRequest['requestUrl']) +'.counter': 1 }})
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_status.' + inputRequest['code'] +'.counter': 1 }})
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_method.' + inputRequest['method'] +'.counter': 1 }})
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_geo.' + helper.GeoLocate(inputRequest['ip'], True) + '.counter': 1 }})

	## INVESTIGATE ####
	bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_conn.' + otherkeyValue.replace('.', '_') + '.counter': 1 }})


	#### Add querystring param ####
	if len(queryString) > 0:
		for param in queryString:
			if len(param.split('=')) == 2:
				pKey = param.split('=')[0]
				pValue = '-' if not param.split('=')[1] else param.split('=')[1]


				#### Determine type of param ####
				try:
					int(pValue)
					paramType = 'int'
				except ValueError:
					paramType = 'bool' if pValue == 'true' or pValue == 'false' else 'string'
				except Exception:
					print param


				#### Detecting special chars in param ####
				chars = 'special' if any(char in string.punctuation for char in pValue) else 'normal'


				#### Add to bulk updates ####
				bulk.find({'_id': keyValue }).update_one({'$set': { 'metric_param.' + pKey + '.characters': chars}})
				bulk.find({'_id': keyValue }).update_one({'$set': { 'metric_param.' + pKey + '.type': paramType}})
				bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_param.' + pKey + '.' + pValue + '.counter': 1}})
				bulk.find({'_id': keyValue }).update_one({'$inc': { 'metric_param.' + pKey + '.counter': 1}})


	#### Execute batch ####
	try:
		bulk.execute()
	except Exception:
		pass

	#### Setup timeline ####
	helper.makeTimeline(ProcessedMongo, keyValue, otherkeyValue.replace('.', '_'))


	#### Calculate ratio for metrics ####
	helper.calculateRatio('_id', keyValue, 'metric_geo', ProcessedMongo)
	helper.calculateRatio('_id', keyValue, 'metric_agent', ProcessedMongo)
	helper.calculateRatio('_id', keyValue, 'metric_time', ProcessedMongo)
	helper.calculateRatio('_id', keyValue, 'metric_day', ProcessedMongo)
	helper.calculateRatio('_id', keyValue, 'metric_ext', ProcessedMongo)
	helper.calculateRatio('_id', keyValue, 'metric_request', ProcessedMongo)
	helper.calculateRatio('_id', keyValue, 'metric_status', ProcessedMongo)
	helper.calculateRatio('_id', keyValue, 'metric_method', ProcessedMongo)




	#### Remove from queue ###
	try:
		StreamMongoDB.delete_one({'_id': inputRequest['_id']})
	except Exception:
		print 'Delete failed'


	#### Store all modified fields ####
	return {
		'location': helper.GeoLocate(inputRequest['ip'], True),
		'time': timestamp.strftime("%H"),
		'agent': inputRequest['uagent'].replace('.', '_'),
		'ext': helper.getFileType(inputRequest['requestUrl']),
		'request': helper.getFileType(inputRequest['requestUrl']),
		'status': inputRequest['code'],
		'method': inputRequest['method'],
		'param': queryString
	}






###########################
#### ANOMALY DETECTION ####
###########################

def startAnomalyDetection(packet, profileRecord, tmpLastObj):
	""" Start anomaly detection process """


	requestRecord = ProcessedMongo.find_one({'_id': helper.getUrlWithoutQuery(packet['url'])})

	anomaly_TotalConnections(profileRecord, requestRecord, tmpLastObj)
	anomaly_GeoUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_TimeUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_AgentUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_ExtUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_RequestUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj)

	anomaly_IpStatic(requestRecord, tmpLastObj)



#################
#### UNKNOWS ####
#################

def anomaly_GeoUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in geo metric """

	if tmpLastObj['location'] in profileRecord['metric_geo']:
		anomaly_GeoCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_GeoRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		print '[ALERT] Unknown locations has connected ({})'.format(tmpLastObj['location'])

def anomaly_TimeUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in time metric """

	if tmpLastObj['time'] in profileRecord['metric_time']:
		anomaly_TimeCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_TimeRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		print '[ALERT] Connection at unfamiliar time ({})'.format(tmpLastObj['time'])

def anomaly_AgentUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in agent metric """

	if tmpLastObj['agent'] in profileRecord['metric_agent']:
		anomaly_AgentCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_AgentRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		print '[ALERT] Connection with unfamiliar user agent ({})'.format(tmpLastObj['agent'])

def anomaly_ExtUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in file extension metric """

	if tmpLastObj['ext'] in profileRecord['metric_ext']:
		anomaly_ExtCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_ExtRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		print '[ALERT] Request for unusual file type ({})'.format(tmpLastObj['ext'])

def anomaly_RequestUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in request metric """

	if tmpLastObj['request'] in profileRecord['metric_request']:
		anomaly_RequestCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_RequestRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		print '[ALERT] Unfamiliar resource requested ({})'.format(tmpLastObj['request'])

def anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in parameter metric """

	for param in tmpLastObj['param']:
		if param in profileRecord['metric_param']:
			anomaly_ParamCounter(profileRecord, requestRecord, tmpLastObj)
			anomaly_ParamRatio(profileRecord, requestRecord, tmpLastObj)
		else:
			print '[ALERT] Unfamiliar resource requested ({})'.format(param)


#################
#### STATICS ####
#################

#### only for user profiling ####
def anomaly_IpStatic(requestRecord, tmpLastObj):
	pass
	# print '[Alert] Blocklisted ip detected' if IPReputationMongoDB.find_one({'ip' : requestRecord['ip'] }).count >= 1 else '[OK] IP not blacklisted'


##################
#### COUNTERS ####
##################

def anomaly_TotalConnections (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections """
	diff = int(requestRecord['general_totalConnections']) - int(profileRecord['general_totalConnections'])
	print '[ALERT] Total conncections has been exceeded ({})'.format(diff) if threshold_counter < diff else '[OK] Total connections safe ({})'.format(diff)

def anomaly_GeoCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections from specific country """
	diff = int(requestRecord['metric_geo'][tmpLastObj['location']]['counter']) - int(profileRecord['metric_geo'][tmpLastObj['location']]['counter'])
	print '[ALERT] Total connections from location has been exceeded ({} | {})'.format(diff, tmpLastObj['location']) if threshold_counter < diff else '[OK] Connections from location safe ({} | {})'.format(diff, tmpLastObj['location'])

def anomaly_TimeCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections at specific time """
	diff = int(requestRecord['metric_time'][tmpLastObj['time']]['counter']) - int(profileRecord['metric_time'][tmpLastObj['time']]['counter'])
	print '[ALERT] Total connections at time has been exceeded ({} | {}h)'.format(diff, tmpLastObj['time']) if threshold_counter < diff else '[OK] Connections at time safe ({} | {}h)'.format(diff, tmpLastObj['time'])

def anomaly_AgentCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections with specific agent """
	diff = int(requestRecord['metric_agent'][tmpLastObj['agent']]['counter']) - int(profileRecord['metric_agent'][tmpLastObj['agent']]['counter'])
	print '[ALERT] Total connections from user agent has been exceeded ({} | {})'.format(diff, tmpLastObj['agent']) if threshold_counter < diff else '[OK] Connections from user agent safe ({} | {}h)'.format(diff, tmpLastObj['agent'])

def anomaly_ExtCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections to specific file types """
	diff = int(requestRecord['metric_ext'][tmpLastObj['ext']]['counter']) - int(profileRecord['metric_ext'][tmpLastObj['ext']]['counter'])
	print '[ALERT] Total requests for filetype has been exceeded ({} | {})'.format(diff, tmpLastObj['ext']) if threshold_counter < diff else '[OK] Connections for filetype safe ({} | {})'.format(diff, tmpLastObj['ext'])

def anomaly_RequestCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_request'][tmpLastObj['request']]['counter']) - int(profileRecord['metric_request'][tmpLastObj['request']]['counter'])
	print '[ALERT] Total requests for resource has been exceeded ({} | {})'.format(diff, tmpLastObj['request']) if threshold_counter < diff else '[OK] Requests for resource safe ({} | {})'.format(diff, tmpLastObj['request'])

def anomaly_StatusCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_status'][tmpLastObj['status']]['counter']) - int(profileRecord['metric_status'][tmpLastObj['status']]['counter'])
	print '[ALERT] More status than usual ({} | {})'.format(diff, tmpLastObj['status']) if threshold_counter < diff else '[OK] Status for resource safe ({} | {})'.format(diff, tmpLastObj['status'])

def anomaly_MethodCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_method'][tmpLastObj['method']]['counter']) - int(profileRecord['metric_method'][tmpLastObj['method']]['counter'])
	print '[ALERT] More methods than usual ({} | {})'.format(diff, tmpLastObj['method']) if threshold_counter < diff else '[OK] Methods for resource safe ({} | {})'.format(diff, tmpLastObj['method'])

def anomaly_ParamCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections on specific querystring parameter """
	for param in tmpLastObj['param']:
		diff = int(requestRecord['metric_param'][param]['counter']) - int(profileRecord['metric_param'][param]['counter'])
		print '[ALERT] Total requests with parameter has been exceeded ({} | {})'.format(diff, param) if threshold_counter < diff else '[OK] Connections with parameter safe ({} | {})'.format(diff, param)



################
#### RATIOS ####
################

def anomaly_GeoRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent geolocation ratio """
	diff = float(requestRecord['metric_geo'][tmpLastObj['location']]['ratio']) - float(profileRecord['metric_geo'][tmpLastObj['location']]['ratio'])
	print '[OK] Ratio geolocation safe ({} | {})'.format(diff, tmpLastObj['location']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio geolocation has been exceeded ({} | {})'.format(diff, tmpLastObj['location'])

def anomaly_TimeRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent time ratio """
	diff = float(requestRecord['metric_time'][tmpLastObj['time']]['ratio']) - float(profileRecord['metric_time'][tmpLastObj['time']]['ratio'])
	print '[OK] Ratio time safe ({} | {}h)'.format(diff, tmpLastObj['time']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio time has been exceeded ({} | {}h)'.format(diff, tmpLastObj['time'])

def anomaly_AgentRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent agent ratio """
	diff = float(requestRecord['metric_agent'][tmpLastObj['agent']]['ratio']) - float(profileRecord['metric_agent'][tmpLastObj['agent']]['ratio'])
	print '[OK] Ratio user agent safe ({} | {})'.format(diff, tmpLastObj['agent']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio user agent has been exceeded ({} | {})'.format(diff, tmpLastObj['agent'])

def anomaly_ExtRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent file type ratio """
	diff = float(requestRecord['metric_ext'][tmpLastObj['ext']]['ratio']) - float(profileRecord['metric_ext'][tmpLastObj['ext']]['ratio'])
	print '[OK] Ratio file extension safe ({} | {})'.format(diff, tmpLastObj['ext']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio file extension has been exceeded ({} | {})'.format(diff, tmpLastObj['ext'])

def anomaly_RequestRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent request ratio """
	diff = float(requestRecord['metric_request'][tmpLastObj['request']]['ratio']) - float(profileRecord['metric_request'][tmpLastObj['request']]['ratio'])
	print '[OK] Ratio resource requests safe ({} | {})'.format(diff, tmpLastObj['request']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio resource requests has been exceeded ({} | {})'.format(diff, tmpLastObj['request'])

def anomaly_StatusRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent request ratio """
	diff = float(requestRecord['metric_status'][tmpLastObj['request']]['ratio']) - float(profileRecord['metric_status'][tmpLastObj['request']]['ratio'])
	print '[OK] Ratio status safe ({} | {})'.format(diff, tmpLastObj['request']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio status has been exceeded ({} | {})'.format(diff, tmpLastObj['request'])

def anomaly_MethodRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent request ratio """
	diff = float(requestRecord['metric_method'][tmpLastObj['request']]['ratio']) - float(profileRecord['metric_method'][tmpLastObj['request']]['ratio'])
	print '[OK] Ratio method safe ({} | {})'.format(diff, tmpLastObj['request']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio method has been exceeded ({} | {})'.format(diff, tmpLastObj['request'])

def anomaly_ParamRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent param ratio """
	for param in tmpLastObj['param']:
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


			## User filtering
			tmpLastObj = processRequest(packet, packet['ip'], helper.getUrlWithoutQuery(packet['url']))

			## App filtering
			tmpLastObj = processRequest(packet, helper.getUrlWithoutQuery(packet['url']), packet['ip'])




			startAnomalyDetection(packet, ProfileAppMongoDB.find_one({'_id': helper.getUrlWithoutQuery(packet['url'])}), tmpLastObj)

			print '-----------------'
