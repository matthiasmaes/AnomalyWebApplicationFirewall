import time
from pymongo import MongoClient
import os.path

import sys
sys.path.append('../0. Helper')
from helper import Helper, TYPE, SCRIPT, SEVERITY, FirewallAlarmException


#### Init helper object ####
helperObj = Helper()

#### Init options ####
options, args = helperObj.setupParser()

helperObj.OutputMongoDB = MongoClient().Firewall.processed
ProfileAppMongoDB = MongoClient().profile_app['TEST']
ProfileUserMongoDB = MongoClient().profile_user['TEST']
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
threshold_length = 5
index = 0



###########################
#### ANOMALY DETECTION ####
###########################

def startAnomalyDetection(packet, profileRecord, tmpLastObj, typeProfile):
	""" Start anomaly detection process """

	# Start off by performing the static checks (ip, location...)
	if (anomaly_StaticChecks(packet)):

		# Differentiate between user and app anomaly detection (different keys: ip/url)
		if typeProfile == TYPE.USER:
			requestRecord = helperObj.OutputMongoDB.find_one({'_id': packet['ip']})

			# Perform most basic checks (Total connections)
			anomaly_TotalConnections(profileRecord, requestRecord, tmpLastObj)
			anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj)

			# Iterate over all metrics and perform the standard checks (counter, ratio and average)
			for metric in ProfileUserMongoDB.find_one():
				if 'metric' in metric and 'param' not in metric and 'timespent' not in metric:
					anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj)
				if 'timespent' in metric or 'size' in metric:
					anomaly_GeneralDeviation(metric, profileRecord, requestRecord, tmpLastObj)

		else:
			requestRecord = helperObj.OutputMongoDB.find_one({'_id': helperObj.getUrlWithoutQuery(packet['requestUrl'])})

			# Perform most basic checks (Total connections)
			anomaly_TotalConnections(profileRecord, requestRecord, tmpLastObj)
			anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj)

			# Iterate over all metrics and perform the standard checks (counter, ratio and average)
			for metric in ProfileAppMongoDB.find_one():
				if 'metric' in metric and 'param' not in metric and 'timespent' not in metric:
					anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj)
				if 'timespent' in metric or 'size' in metric:
					anomaly_GeneralDeviation(metric, profileRecord, requestRecord, tmpLastObj)
	else:
		FirewallAlarmException('Static list block', 'ip/uagent', 0, SEVERITY.CRITICAL, tmpLastObj['typeProfile'], tmpLastObj['ip'])




def anomaly_StaticChecks(packet):
	""" Check static blocklist with ips and spam user agent list"""
	return IPReputationMongoDB.find_one({'_id' : packet['ip']}) == None and SpamAgentMongoDB.find_one({'string' : packet['uagent']}) == None


def anomaly_TotalConnections (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections """
	diff = int(requestRecord['general_totalConnections']) - int(profileRecord['general_totalConnections'])
	if threshold_counter < diff: FirewallAlarmException('Counter exceeded', 'general_TotalConnections', diff, SEVERITY.LOW, tmpLastObj['typeProfile'], tmpLastObj['ip'])


def anomaly_GeneralUnknown(metric, profileRecord, requestRecord, tmpLastObj):
	""" Generic method for detecting unknown anomalies for the given metrics """
	if tmpLastObj[metric] in profileRecord[metric]:
		anomaly_GeneralCounter(metric, profileRecord, requestRecord, tmpLastObj)
		anomaly_GeneralRatio(metric, profileRecord, requestRecord, tmpLastObj)
	else:
		if metric != 'metric_size' and metric != 'metric_timespent':
			FirewallAlarmException('Unknown found in', metric, tmpLastObj[metric], SEVERITY.HIGH, tmpLastObj['typeProfile'], tmpLastObj['ip'])

	# Do not detect unknown on min max metrics (timespent, size etc)
	anomaly_GeneralMinMax(metric, profileRecord, requestRecord, tmpLastObj)


def anomaly_GeneralCounter (metric, profileRecord, requestRecord, tmpLastObj):
	""" Generic method for detecting excessive counter on given metric """
	diff = int(requestRecord[metric][tmpLastObj[metric]]['counter']) - int(profileRecord[metric][tmpLastObj[metric]]['counter'])
	if threshold_counter < diff: FirewallAlarmException('Counter exceeded', metric, diff, SEVERITY.LOW, tmpLastObj['typeProfile'], tmpLastObj['ip'])


def anomaly_GeneralRatio(metric, profileRecord, requestRecord, tmpLastObj):
	""" Generic method for detecting excessive ratio on given metric """
	diff = float(requestRecord[metric][tmpLastObj[metric]]['ratio']) - float(profileRecord[metric][tmpLastObj[metric]]['ratio'])
	if not(-threshold_ratio <= diff <= threshold_ratio): FirewallAlarmException('Ratio exceeded', metric, diff, SEVERITY.LOW, tmpLastObj['typeProfile'], tmpLastObj['ip'])


def anomaly_GeneralMinMax(metric, profileRecord, requestRecord, tmpLastObj):
	""" Generic method for detecting anomalies in min max from metrics """

	try:
		# Test on min
		if requestRecord[metric][tmpLastObj['otherkey']]['min'] < profileRecord[metric][tmpLastObj['otherkey']]['min']:
			FirewallAlarmException('Lower min found', metric, requestRecord[metric][tmpLastObj['otherkey']]['min'], SEVERITY.HIGH, tmpLastObj['typeProfile'], tmpLastObj['otherip'])

		# Test on max
		if requestRecord[metric][tmpLastObj['otherkey']]['max'] > profileRecord[metric][tmpLastObj['otherkey']]['max']:
			FirewallAlarmException('Higher max found', metric, requestRecord[metric][tmpLastObj['otherkey']]['max'], SEVERITY.CRITICAL, tmpLastObj['typeProfile'], tmpLastObj['otherip'])
	except KeyError:
		# Not every metric has a min/max defined
		pass


def anomaly_GeneralDeviation(metric, profileRecord, requestRecord, tmpLastObj):
	""" Generic method for detecting anomalies in deviation of average """

	try:
		try:
			newValue = int(tmpLastObj[metric])
			avg = profileRecord[metric][tmpLastObj['otherkey']]['average']
			standev = profileRecord[metric][tmpLastObj['otherkey']]['deviation']
		except ValueError:
			print '[DEBUG] VALUE ERROR'
			return
		except TypeError:
			print '[DEBUG] TYPE ERROR'
			return

		# The further the average deviates the higher the alert becomes

		if newValue not in xrange(int(avg - standev),  int(avg + standev)):
			if newValue in xrange(int(avg - 2 * standev),  int(avg + 2 * standev)):
				FirewallAlarmException('Value deviates between 1 and 2 sigma form average', metric, 'Value (' + str(newValue) + ') within range: ' + str(avg - 2 * standev) + ' | ' + str(avg + 2 * standev) , SEVERITY.HIGH, tmpLastObj['typeProfile'], tmpLastObj['ip'])
			# elif newValue in xrange(int(avg - 3 * standev),  int(avg + 3 * standev)):
			else:
				FirewallAlarmException('Value deviates more than 2 sigma from average', metric, 'Value (' + str(newValue) + ') outside range: ' + str(avg - 2 * standev) + ' | ' + str(avg + 2 * standev) , SEVERITY.CRITICAL, tmpLastObj['typeProfile'], tmpLastObj['ip'])

	except KeyError:
		# Not every metric has a deviation defined
		pass



def anomaly_ParamUnknown(profileRecord, requestRecord, tmpLastObj):
	""" Detect unknowns in parameter metric """


	for analysedParam in tmpLastObj['analysed_param']:
		if analysedParam['key'] in profileRecord['metric_param']:
			anomaly_ParamAnomaly(profileRecord, requestRecord, tmpLastObj)
			anomaly_ParamAnalyzed(profileRecord, analysedParam)
		else:
			FirewallAlarmException('Unknown param', 'metric_param', analysedParam['key'], SEVERITY.HIGH, tmpLastObj['typeProfile'], tmpLastObj['ip'])


def anomaly_ParamAnomaly (profileRecord, requestRecord, tmpLastObj):
	""" Detect to many connections on specific querystring parameter """
	for analysedParam in tmpLastObj['analysed_param']:
		diff = int(requestRecord['metric_param'][analysedParam['key']]['counter']) - int(profileRecord['metric_param'][analysedParam['key']]['counter'])
		if threshold_counter < diff: FirewallAlarmException('Counter exceeded', 'metric_param', diff, SEVERITY.LOW, tmpLastObj['typeProfile'], tmpLastObj['ip'])

		# diff = float(requestRecord['metric_param'][analysedParam['key']]['ratio']) - float(profileRecord['metric_param'][analysedParam['key']]['ratio'])
		# if -threshold_ratio <= diff <= threshold_ratio: FirewallAlarmException('Param exceeded', 'metric_param', diff, SEVERITY.LOW, tmpLastObj['typeProfile'], tmpLastObj['ip'])


def anomaly_ParamAnalyzed (profileRecord, analysedParam):

	# Test for type
	if analysedParam['type'] != profileRecord['metric_param'][analysedParam['key']]['type']:
		FirewallAlarmException('Param type mismatch', 'metric_param', 'Expected: ' + profileRecord['metric_param'][analysedParam['key']]['type'] + ' - Received: ' + analysedParam['type'] + ' - ON PARAM: ' + analysedParam['key'], SEVERITY.HIGH, tmpLastObj['typeProfile'], tmpLastObj['ip'])

	# Test for chars
	if analysedParam['characters'] != profileRecord['metric_param'][analysedParam['key']]['characters']:
		FirewallAlarmException('Param characters mismatch', 'metric_param', 'Expected: ' + profileRecord['metric_param'][analysedParam['key']]['characters'] + ' - Received: ' + analysedParam['characters'] + ' - ON PARAM: ' + analysedParam['key'], SEVERITY.CRITICAL, tmpLastObj['typeProfile'], tmpLastObj['ip'])

	# Test for length
	if abs(analysedParam['length'] - profileRecord['metric_param'][analysedParam['key']]['length']) > threshold_length:
		FirewallAlarmException('Param length mismatch', 'metric_param', 'Expected: ' + str(profileRecord['metric_param'][analysedParam['key']]['length']) + ' - Received: ' + str(analysedParam['length']) + ' - ON PARAM: ' + analysedParam['key'], SEVERITY.LOW, tmpLastObj['typeProfile'], tmpLastObj['ip'])




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



	if os.path.exists('C:/wamp64/logs/access.log'):
		path = 'C:/wamp64/logs/access.log'
	elif os.path.exists('/var/log/nginx/access.log'):
		path = '/var/log/nginx/access.log'

	with open(path) as fileobject:

		print ' - [LOG] [OK] Ready to start processing requests...'
		fileobject.seek(0,2)

		while True:
			inputLine = fileobject.readline()

			if inputLine != '':
				print '===== Starting Analysis ====='
				print 'INPUT: ', inputLine

				#### Create line object and insert it in mongodb
				lineObj = helperObj.processLine(inputLine, index)


				## App filtering
				print '\n----- App analysis -----'
				tmpLastObj = helperObj.processLineCombined(TYPE.APP, SCRIPT.FIREWALL, lineObj, options)


				if ProfileAppMongoDB.find({'_id': helperObj.getUrlWithoutQuery(lineObj['requestUrl'])}).count() > 0:
					startAnomalyDetection(lineObj, ProfileAppMongoDB.find_one({'_id': helperObj.getUrlWithoutQuery(lineObj['requestUrl'])}), tmpLastObj, TYPE.APP)
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