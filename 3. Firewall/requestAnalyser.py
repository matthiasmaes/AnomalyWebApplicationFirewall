import datetime
from pymongo import MongoClient

import sys
sys.path.append('C:/Users/bebxadvmmae/Desktop/REMOTE/0. Helper')
from helper import Helper, TYPE, SCRIPT
from formattedLine import FormattedLine


#### Init helper object ####
helperObj = Helper()

#### Init options ####
options, args = helperObj.setupParser()

helperObj.OutputMongoDB = MongoClient().Firewall.processed
ProfileAppMongoDB = MongoClient().profile_app['TEST']
ProfileUserMongoDB = MongoClient().profile_user['TEST']
MessageMongoDB = MongoClient().engine_log.firewall_messages

IPReputationMongoDB = MongoClient().config_static.firewall_blocklist
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

	if (anomaly_IpStatic(packet['ip'])):

		if typeProfile == TYPE.USER:
			requestRecord = helperObj.OutputMongoDB.find_one({'_id': packet['ip']})
			anomaly_TotalConnections(profileRecord, requestRecord)
			for metric in ProfileUserMongoDB.find_one():
				if 'metric' in metric and 'param' not in metric and 'timespent' not in metric:
					anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj)


		else:
			requestRecord = helperObj.OutputMongoDB.find_one({'_id': helperObj.getUrlWithoutQuery(packet['url'])})
			anomaly_TotalConnections(profileRecord, requestRecord)
			for metric in ProfileAppMongoDB.find_one():
				if 'metric' in metric and 'param' not in metric and 'timespent' not in metric:
					anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj)

	else:
		print 'IP IS BLACKLISTED'




def anomaly_IpStatic(ip):
	return IPReputationMongoDB.find_one({'_id' : ip}) == None


def anomaly_TotalConnections (profileRecord, requestRecord):
	""" Detect to many connections """

	diff = int(requestRecord['general_totalConnections']) - int(profileRecord['general_totalConnections'])
	result = '[ALERT] Total conncections has been exceeded ({})'.format(diff) if threshold_counter < diff else '[OK] Total connections safe ({})'.format(diff)
	if '[OK]' not in result: reportGeneralAlert('Counter exceeded', 'general_TotalConnections', diff)


def anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj):

	if tmpLastObj[metric] in profileRecord[metric]:
		anomaly_GeneralCounter(metric, profileRecord, requestRecord, tmpLastObj)
		anomaly_GeneralRatio(metric, profileRecord, requestRecord, tmpLastObj)
	else:
		reportGeneralAlert('Unknown found in', metric, tmpLastObj[metric])


def anomaly_GeneralCounter (metric, profileRecord, requestRecord, tmpLastObj):
	diff = int(requestRecord[metric][tmpLastObj[metric]]['counter']) - int(profileRecord[metric][tmpLastObj[metric]]['counter'])
	if threshold_counter < diff: reportGeneralAlert('Counter exceeded', metric, diff)


def anomaly_GeneralRatio(metric, profileRecord, requestRecord, tmpLastObj):
	""" Detect divergent status ratio """
	diff = float(requestRecord[metric][tmpLastObj[metric]]['ratio']) - float(profileRecord[metric][tmpLastObj[metric]]['ratio'])
	if -threshold_ratio <= diff <= threshold_ratio: reportGeneralAlert('Ratio exceeded', metric, diff)


def reportGeneralAlert(msg, metric, details):
	timestamp = datetime.datetime.now().strftime('[%d/%m/%Y][%H:%M:%S]')
	MessageMongoDB.insert_one({'message':  timestamp + '[ALERT] ' + msg + ' (' + metric + ', ' + str(details) + ')'})
	print timestamp + '[ALERT] ' + msg + ' (' + metric + ', ' + str(details) + ')'





##############
#### MAIN ####
##############

if __name__ == '__main__':
	print 'Waiting for packet...'

	import time
	with open('C:/wamp64/logs/access.log') as fileobject:
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