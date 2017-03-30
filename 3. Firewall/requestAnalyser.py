import calendar
import datetime
from pymongo import MongoClient
from record import Record

from helper import Helper

ProcessedMongo = MongoClient().Firewall.processed
StreamMongoDB = MongoClient().Firewall.TestStream
ProfileAppMongoDB = MongoClient().profile_app['profile_app_11:35:52']
ProfileUserMongoDB = MongoClient().profile_user['profile_user_10:52:35']
MessageMongoDB = MongoClient().engine_log.firewall_messages

IPReputationMongoDB = MongoClient().config_static.firewall_blocklist
BotMongoDB = MongoClient().config_static.profile_bots

threshold_ratio = 0.1
threshold_counter = 5

#### Init helper object ####
helperObj = Helper()

#### Init options ####
options, args = helperObj.setupParser()


class TYPE:
	USER, APP = range(2)


###########################
#### ANOMALY DETECTION ####
###########################

def startAnomalyDetection(packet, profileRecord, tmpLastObj, typeProfile):
	""" Start anomaly detection process """


	requestRecord = ProcessedMongo.find_one({'_id': helper.getUrlWithoutQuery(packet['url'])})

	anomaly_TotalConnections(profileRecord, requestRecord, tmpLastObj)
	anomaly_GeoUnknown(profileRecord, requestRecord, tmpLastObj, typeProfile)
	anomaly_TimeUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_AgentUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_ExtUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_RequestUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj)

	anomaly_StatusUnknown(profileRecord, requestRecord, tmpLastObj)
	anomaly_MethodUnknown(profileRecord, requestRecord, tmpLastObj)



#################
#### UNKNOWS ####
#################

def anomaly_GeoUnknown(profileRecord, requestRecord, tmpLastObj, typeProfile):
	""" Detect unknowns in geo metric """

	if typeProfile == TYPE.USER:
		# anomaly_IpStatic(requestRecord, tmpLastObj)

		if tmpLastObj['location'] != profileRecord['general_location']:
			result = '[ALARM] IP changed from location'
	else:
		if tmpLastObj['location'] in profileRecord['metric_geo']:
			anomaly_GeoCounter(profileRecord, requestRecord, tmpLastObj)
			anomaly_GeoRatio(profileRecord, requestRecord, tmpLastObj)
		else:
			result = '[ALERT] Unknown locations has connected ({})'.format(tmpLastObj['location'])
			if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_TimeUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in time metric """

	if tmpLastObj['time'] in profileRecord['metric_time']:
		anomaly_TimeCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_TimeRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		result = '[ALERT] Connection at unfamiliar time ({})'.format(tmpLastObj['time'])
		if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_AgentUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in agent metric """

	if tmpLastObj['agent'] in profileRecord['metric_agent']:
		anomaly_AgentCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_AgentRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		result = '[ALERT] Connection with unfamiliar user agent ({})'.format(tmpLastObj['agent'])
		if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_ExtUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in file extension metric """

	if tmpLastObj['ext'] in profileRecord['metric_ext']:
		anomaly_ExtCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_ExtRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		result = '[ALERT] Request for unusual file type ({})'.format(tmpLastObj['ext'])
		if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_RequestUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in request metric """

	if tmpLastObj['request'] in profileRecord['metric_request']:
		anomaly_RequestCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_RequestRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		result = '[ALERT] Unfamiliar resource requested ({})'.format(tmpLastObj['request'])
		if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_StatusUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in status metric """

	if tmpLastObj['status'] in profileRecord['metric_status']:
		anomaly_StatusCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_StatusRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		result = '[ALERT] Unfamiliar status request ({})'.format(tmpLastObj['status'])
		if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})


def anomaly_MethodUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in method metric """

	if tmpLastObj['method'] in profileRecord['metric_method']:
		anomaly_MethodCounter(profileRecord, requestRecord, tmpLastObj)
		anomaly_MethodRatio(profileRecord, requestRecord, tmpLastObj)
	else:
		result = '[ALERT] Unfamiliar method request ({})'.format(tmpLastObj['method'])
		if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})






def anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in parameter metric """

	for param in tmpLastObj['param']:
		if param in profileRecord['metric_param']:
			anomaly_ParamCounter(profileRecord, requestRecord, tmpLastObj)
			anomaly_ParamRatio(profileRecord, requestRecord, tmpLastObj)
		else:
			result = '[ALERT] Unfamiliar resource requested ({})'.format(param)
			if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})


#################
#### STATICS ####
#################

#### only for user profiling ####
def anomaly_IpStatic(requestRecord, tmpLastObj):
	result = '[Alert] Blocklisted ip detected' if IPReputationMongoDB.find_one({'_id' : requestRecord['_id'] }).count >= 1 else '[OK] IP not blacklisted'
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})


##################
#### COUNTERS ####
##################

def anomaly_TotalConnections (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections """
	diff = int(requestRecord['general_totalConnections']) - int(profileRecord['general_totalConnections'])
	result = '[ALERT] Total conncections has been exceeded ({})'.format(diff) if threshold_counter < diff else '[OK] Total connections safe ({})'.format(diff)
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_GeoCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections from specific country """
	diff = int(requestRecord['metric_geo'][tmpLastObj['location']]['counter']) - int(profileRecord['metric_geo'][tmpLastObj['location']]['counter'])
	result = '[ALERT] Total connections from location has been exceeded ({} | {})'.format(diff, tmpLastObj['location']) if threshold_counter < diff else '[OK] Connections from location safe ({} | {})'.format(diff, tmpLastObj['location'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_TimeCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections at specific time """
	diff = int(requestRecord['metric_time'][tmpLastObj['time']]['counter']) - int(profileRecord['metric_time'][tmpLastObj['time']]['counter'])
	result = '[ALERT] Total connections at time has been exceeded ({} | {}h)'.format(diff, tmpLastObj['time']) if threshold_counter < diff else '[OK] Connections at time safe ({} | {}h)'.format(diff, tmpLastObj['time'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_AgentCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections with specific agent """
	diff = int(requestRecord['metric_agent'][tmpLastObj['agent']]['counter']) - int(profileRecord['metric_agent'][tmpLastObj['agent']]['counter'])
	result = '[ALERT] Total connections from user agent has been exceeded ({} | {})'.format(diff, tmpLastObj['agent']) if threshold_counter < diff else '[OK] Connections from user agent safe ({} | {}h)'.format(diff, tmpLastObj['agent'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_ExtCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections to specific file types """
	diff = int(requestRecord['metric_ext'][tmpLastObj['ext']]['counter']) - int(profileRecord['metric_ext'][tmpLastObj['ext']]['counter'])
	result = '[ALERT] Total requests for filetype has been exceeded ({} | {})'.format(diff, tmpLastObj['ext']) if threshold_counter < diff else '[OK] Connections for filetype safe ({} | {})'.format(diff, tmpLastObj['ext'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_RequestCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_request'][tmpLastObj['request']]['counter']) - int(profileRecord['metric_request'][tmpLastObj['request']]['counter'])
	result = '[ALERT] Total requests for resource has been exceeded ({} | {})'.format(diff, tmpLastObj['request']) if threshold_counter < diff else '[OK] Requests for resource safe ({} | {})'.format(diff, tmpLastObj['request'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_StatusCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_status'][tmpLastObj['status']]['counter']) - int(profileRecord['metric_status'][tmpLastObj['status']]['counter'])
	result = '[ALERT] More status than usual ({} | {})'.format(diff, tmpLastObj['status']) if threshold_counter < diff else '[OK] Status for resource safe ({} | {})'.format(diff, tmpLastObj['status'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_MethodCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections to specific resource file """
	diff = int(requestRecord['metric_method'][tmpLastObj['method']]['counter']) - int(profileRecord['metric_method'][tmpLastObj['method']]['counter'])
	result = '[ALERT] More methods than usual ({} | {})'.format(diff, tmpLastObj['method']) if threshold_counter < diff else '[OK] Methods for resource safe ({} | {})'.format(diff, tmpLastObj['method'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_ParamCounter (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections on specific querystring parameter """
	for param in tmpLastObj['param']:
		diff = int(requestRecord['metric_param'][param]['counter']) - int(profileRecord['metric_param'][param]['counter'])
		result = '[ALERT] Total requests with parameter has been exceeded ({} | {})'.format(diff, param) if threshold_counter < diff else '[OK] Connections with parameter safe ({} | {})'.format(diff, param)
		if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})



################
#### RATIOS ####
################

def anomaly_GeoRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent geolocation ratio """
	diff = float(requestRecord['metric_geo'][tmpLastObj['location']]['ratio']) - float(profileRecord['metric_geo'][tmpLastObj['location']]['ratio'])
	result = '[OK] Ratio geolocation safe ({} | {})'.format(diff, tmpLastObj['location']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio geolocation has been exceeded ({} | {})'.format(diff, tmpLastObj['location'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_TimeRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent time ratio """
	diff = float(requestRecord['metric_time'][tmpLastObj['time']]['ratio']) - float(profileRecord['metric_time'][tmpLastObj['time']]['ratio'])
	result = '[OK] Ratio time safe ({} | {}h)'.format(diff, tmpLastObj['time']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio time has been exceeded ({} | {}h)'.format(diff, tmpLastObj['time'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_AgentRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent agent ratio """
	diff = float(requestRecord['metric_agent'][tmpLastObj['agent']]['ratio']) - float(profileRecord['metric_agent'][tmpLastObj['agent']]['ratio'])
	result = '[OK] Ratio user agent safe ({} | {})'.format(diff, tmpLastObj['agent']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio user agent has been exceeded ({} | {})'.format(diff, tmpLastObj['agent'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_ExtRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent file type ratio """
	diff = float(requestRecord['metric_ext'][tmpLastObj['ext']]['ratio']) - float(profileRecord['metric_ext'][tmpLastObj['ext']]['ratio'])
	result = '[OK] Ratio file extension safe ({} | {})'.format(diff, tmpLastObj['ext']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio file extension has been exceeded ({} | {})'.format(diff, tmpLastObj['ext'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_RequestRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent request ratio """
	diff = float(requestRecord['metric_request'][tmpLastObj['request']]['ratio']) - float(profileRecord['metric_request'][tmpLastObj['request']]['ratio'])
	result = '[OK] Ratio resource requests safe ({} | {})'.format(diff, tmpLastObj['request']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio resource requests has been exceeded ({} | {})'.format(diff, tmpLastObj['request'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_StatusRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent status ratio """
	diff = float(requestRecord['metric_status'][tmpLastObj['status']]['ratio']) - float(profileRecord['metric_status'][tmpLastObj['status']]['ratio'])
	result = '[OK] Ratio status safe ({} | {})'.format(diff, tmpLastObj['status']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio status has been exceeded ({} | {})'.format(diff, tmpLastObj['status'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_MethodRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent method ratio """
	diff = float(requestRecord['metric_method'][tmpLastObj['method']]['ratio']) - float(profileRecord['metric_method'][tmpLastObj['method']]['ratio'])
	result = '[OK] Ratio method safe ({} | {})'.format(diff, tmpLastObj['method']) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio method has been exceeded ({} | {})'.format(diff, tmpLastObj['method'])
	if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})

def anomaly_ParamRatio(profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent param ratio """
	for param in tmpLastObj['param']:
		diff = float(requestRecord['metric_param'][param]['ratio']) - float(profileRecord['metric_param'][param]['ratio'])
		result = '[OK] Ratio resource requests safe ({} | {})'.format(diff, param) if -threshold_ratio <= diff <= threshold_ratio else '[ALERT] Ratio resource requests has been exceeded ({} | {})'.format(diff, param)
		if '[OK]' not in result: MessageMongoDB.insert_one({'message': result})


##############
#### MAIN ####
##############

if __name__ == '__main__':
	print 'Waiting for packet...'
	while True:
		for inputLine in StreamMongoDB.find():
			print 'Started processing'


			## App filtering
			tmpLastObj = helperObj.processLineCombined(TYPE.APP, inputLine, options)
			startAnomalyDetection(inputLine, ProfileAppMongoDB.find_one({'_id': helper.getUrlWithoutQuery(inputLine['url'])}), tmpLastObj, TYPE.APP)


			## User filtering
			tmpLastObj = helperObj.processLineCombined(TYPE.USER, inputLine, options)
			startAnomalyDetection(inputLine, ProfileUserMongoDB.find_one({'_id': inputLine['ip']}), tmpLastObj, TYPE.USER)



			#### Remove from queue ###
			try:
				StreamMongoDB.delete_one({'_id': inputRequest['_id']})
			except Exception:
				print 'Delete failed'


			# #### Store all modified fields ####
			# return {
			# 	'location': helper.GeoLocate(inputRequest['ip'], True),
			# 	'time': timestamp.strftime("%H"),
			# 	'agent': inputRequest['uagent'].replace('.', '_'),
			# 	'ext': helper.getFileType(inputRequest['requestUrl']),
			# 	'request': inputRequest['requestUrl'].replace('.', '_'),
			# 	'status': inputRequest['code'],
			# 	'method': inputRequest['method'],
			# 	'param': queryString
			# }



			print '-----------------'