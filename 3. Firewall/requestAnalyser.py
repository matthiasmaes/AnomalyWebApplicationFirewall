import datetime, time
from pymongo import MongoClient

import sys
sys.path.append('C:/Users/bebxadvmmae/Desktop/REMOTE/0. Helper')
from helper import Helper, TYPE, SCRIPT, SEVERITY


#### Init helper object ####
helperObj = Helper()

#### Init options ####
options, args = helperObj.setupParser()

helperObj.OutputMongoDB = MongoClient().Firewall.processed
ProfileAppMongoDB = MongoClient().profile_app['TEST']
ProfileUserMongoDB = MongoClient().profile_user['TEST']
MessageMongoDB = MongoClient().engine_log.firewall_messages

IPReputationMongoDB = MongoClient().config_static.firewall_blocklist
SpamAgentMongoDB = MongoClient().config_static.profile_extended_spam

helperObj.BotMongoDB = MongoClient().config_static.profile_bots


#### Get list of admin strings ####
AdminMongoList = []
for admin in MongoClient().config_static.profile_admin.find():
	AdminMongoList.append(admin['name'])
helperObj.AdminMongoList = AdminMongoList

#### Get list of user strings ####
UserMongoList = []
for user in MongoClient().config_static.profile_user.find():
	UserMongoList.append(user['name'])
helperObj.UserMongoList = UserMongoList


threshold_ratio = 0.1
threshold_counter = 5
index = 0


###########################
#### ANOMALY DETECTION ####
###########################

def startAnomalyDetection(packet, profileRecord, tmpLastObj, typeProfile):
	""" Start anomaly detection process """

	if (anomaly_StaticChecks(packet)):

		if typeProfile == TYPE.USER:
			requestRecord = helperObj.OutputMongoDB.find_one({'_id': packet['ip']})
			anomaly_TotalConnections(profileRecord, requestRecord)
			anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj)
			anomaly_GeneralMinMax(profileRecord, requestRecord, tmpLastObj)

			for metric in ProfileUserMongoDB.find_one():
				if 'metric' in metric and 'param' not in metric and 'timespent' not in metric:
					anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj)


		else:
			requestRecord = helperObj.OutputMongoDB.find_one({'_id': helperObj.getUrlWithoutQuery(packet['url'])})
			anomaly_TotalConnections(profileRecord, requestRecord)
			anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj)
			anomaly_GeneralMinMax(profileRecord, requestRecord, tmpLastObj)

			for metric in ProfileAppMongoDB.find_one():
				if 'metric' in metric and 'param' not in metric and 'timespent' not in metric:
					anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj)



	else:
		report_GeneralAlert('Static list block', 'ip/uagent', diff, SEVERITY.CRITICAL)




def anomaly_StaticChecks(packet):
	""" Check static blocklist with ips """
	return IPReputationMongoDB.find_one({'_id' : packet['ip']}) == None and SpamAgentMongoDB.find_one({'string' : packet['uagent']}) == None


def anomaly_TotalConnections (profileRecord, requestRecord):
	""" Detect to many connections """
	diff = int(requestRecord['general_totalConnections']) - int(profileRecord['general_totalConnections'])
	if threshold_counter < diff: report_GeneralAlert('Counter exceeded', 'general_TotalConnections', diff, SEVERITY.LOW)


def anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj):
	""" Generic method for detecting unknown anomalies for the given metrics """
	if tmpLastObj[metric] in profileRecord[metric]:
		anomaly_GeneralCounter(metric, profileRecord, requestRecord, tmpLastObj)
		anomaly_GeneralRatio(metric, profileRecord, requestRecord, tmpLastObj)
	else:
		report_GeneralAlert('Unknown found in', metric, tmpLastObj[metric], SEVERITY.HIGH)


def anomaly_GeneralCounter (metric, profileRecord, requestRecord, tmpLastObj):
	""" Generic method for detecting excessive counter on given metric """
	diff = int(requestRecord[metric][tmpLastObj[metric]]['counter']) - int(profileRecord[metric][tmpLastObj[metric]]['counter'])
	if threshold_counter < diff: report_GeneralAlert('Counter exceeded', metric, diff, SEVERITY.LOW)


def anomaly_GeneralRatio(metric, profileRecord, requestRecord, tmpLastObj):
	""" Generic method for detecting excessive ratio on given metric """
	diff = float(requestRecord[metric][tmpLastObj[metric]]['ratio']) - float(profileRecord[metric][tmpLastObj[metric]]['ratio'])
	if -threshold_ratio >= diff >= threshold_ratio: report_GeneralAlert('Ratio exceeded', metric, diff, SEVERITY.LOW)


def anomaly_GeneralMinMax(metric, profileRecord, requestRecord, tmpLastObj):
	try:
		if requestRecord[metric][tmpLastObj['_id']]['min'] < profileRecord[metric][tmpLastObj['_id']]['min']:
			report_GeneralAlert('Lower min found', metric, requestRecord[metric][tmpLastObj['_id']]['min'], SEVERITY.HIGH)

		if requestRecord[metric][tmpLastObj['_id']]['max'] > profileRecord[metric][tmpLastObj['_id']]['max']:
			report_GeneralAlert('Higher max found', metric, requestRecord[metric][tmpLastObj['_id']]['max'], SEVERITY.CRITICAL)
	except KeyError:
		pass


def anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in parameter metric """

	for param in tmpLastObj['metric_param']:
		if param in profileRecord['metric_param']:
			anomaly_ParamAnomaly(profileRecord, requestRecord, tmpLastObj)
		else:
			report_GeneralAlert('Unknown param', 'metric_param', param, SEVERITY.HIGH)


def anomaly_ParamAnomaly (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections on specific querystring parameter """
	for param in tmpLastObj['metric_param']:
		diff = int(requestRecord['metric_param'][param]['counter']) - int(profileRecord['metric_param'][param]['counter'])
		if threshold_counter < diff: report_GeneralAlert('Counter exceeded', 'metric_param', diff, SEVERITY.LOW)

		diff = float(requestRecord['metric_param'][param]['ratio']) - float(profileRecord['metric_param'][param]['ratio'])
		if -threshold_ratio <= diff <= threshold_ratio: report_GeneralAlert('Param exceeded', 'metric_param', diff, SEVERITY.LOW)








def report_GeneralAlert(msg, metric, details, severity):
	""" Add timestamp and report incident to the firewall """
	timestamp = datetime.datetime.now().strftime('[%d/%m/%Y][%H:%M:%S]')
	MessageMongoDB.insert_one({'severity': severity, 'timestamp': timestamp, 'message':  timestamp + '[ALERT] ' + msg + ' (' + metric + ', ' + str(details) + ')'})
	print timestamp + '[ALERT] ' + msg + ' (' + metric + ', ' + str(details) + ')'

















##############
#### MAIN ####
##############

if __name__ == '__main__':


	print '   ,_____ ,'
	print '  ,._ ,_.  |'
	print ' j `-`     |'
	print ' |o_, o    |'
	print '.`_y_`-,`   !'
	print '|/   `, `._ `-,'
	print '|_     \   _.`*|'
	print '  >--,-``-`*_*```---.'
	print '  |\_* _*`-`         `'
	print ' /        WAF         |'
	print ' \. By Matthias Maes  /'
	print '  ``._     /   )     /'
	print '   \  |`-,-|  /c-`7 /'
	print '    ) \ (_,| |   / (_'
	print '   ((_/   ((_;)  \_)))'
	print '==========================='
	print '==========================='


	print '\n\n\n - [LOG] [OK] Firewall started correctly...'

	with open('C:/wamp64/logs/access.log') as fileobject:

		print ' - [LOG] [OK] Ready to start processing requests...'
		fileobject.seek(0,2)

		while True:
			inputLine = fileobject.readline()

			if inputLine != '':
				print '===== Starting Analysis ====='
				print inputLine

				#### Create line object and insert it in mongodb
				lineObj = helperObj.processLine(inputLine, index)


				## App filtering
				print '\n----- App analysis -----'
				tmpLastObj = helperObj.processLineCombined(TYPE.APP, SCRIPT.FIREWALL, lineObj, options)


				print helperObj.getUrlWithoutQuery(lineObj['url'])

				if ProfileAppMongoDB.find({'_id': helperObj.getUrlWithoutQuery(lineObj['url'])}).count() > 0:
					startAnomalyDetection(lineObj, ProfileAppMongoDB.find_one({'_id': helperObj.getUrlWithoutQuery(lineObj['url'])}), tmpLastObj, TYPE.APP)
				else:
					print 'Not profiled page'


				## User filtering
				print '\n----- User analysis -----'
				tmpLastObj = helperObj.processLineCombined(TYPE.USER, SCRIPT.FIREWALL, lineObj, options)

				if ProfileUserMongoDB.find({'_id': lineObj['ip']}).count() > 0:
					startAnomalyDetection(lineObj, ProfileUserMongoDB.find_one({'_id': lineObj['ip']}), tmpLastObj, TYPE.USER)
				else:
					print 'Not profiled user'


				print '===== Analysis Finished =====\n\n\n\n\n'

			else:
				time.sleep(1)