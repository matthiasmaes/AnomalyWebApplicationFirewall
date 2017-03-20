import progressbar
import string
import datetime
import threading
import math

import helper

from collections import OrderedDict

from pymongo import MongoClient
from optparse import OptionParser
from record_user import Record_User



#### Init global vars ####
initTime = str('%02d' % datetime.datetime.now().hour) + ':' +  str('%02d' % datetime.datetime.now().minute) + ':' +  str('%02d' % datetime.datetime.now().second)
startTime = datetime.datetime.now()
converted, activeWorkers = 0, 0

#### Init options ####
options, args = helper.setupParser()


#### Init DB ####
OutputMongoDB = MongoClient().profile_user['profile_user_' + initTime]
InputMongoDB = MongoClient().FormattedLogs[options.inputMongo]
BotMongoDB = MongoClient().config_static.profile_bots


#### Place index on url field to speed up searches through db ####
OutputMongoDB.create_index('url', background=True)


#### Determening lines to process####
options.endindex = InputMongoDB.count() if int(options.endindex) == 0 else int(options.endindex)
diffLines = int(options.endindex) - int(options.startIndex) + 1


#### Preparing progress bar ####
progressBarObj = progressbar.ProgressBar(maxval=diffLines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
progressBarObj.start()



def processLine(start, index):
	""" Assign workers with workload """

	global converted

	for inputLine in InputMongoDB.find()[start : start + int(options.linesPerThread)]:

		#### Ending conditions ####
		if inputLine is None:
			continue

		if converted >= diffLines:
			print 'break on: ' + str(converted)
			break
		else:
			progressBarObj.update(converted)



		#### Replace points in url to prevent confict in mongoDB datastructure ####
		timestamp = datetime.datetime.strptime(inputLine['fulltime'].split(' ')[0], '%d/%b/%Y:%H:%M:%S')
		urlWithoutQuery = helper.getUrlWithoutQuery(inputLine['url']).replace('.', '_')
		queryString = [element.replace('.', '_') for element in helper.getQueryString(inputLine['url'])]


		#### Insert record if it doesn't exists ####
		if OutputMongoDB.find({'general_ip': inputLine['ip']}).count() == 0:
			OutputMongoDB.insert_one(Record_User(inputLine['ip'], helper.GeoLocate(inputLine['ip'], options.ping)).__dict__)


		#### Setup bulk stream ####
		bulk = OutputMongoDB.initialize_unordered_bulk_op()

		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'general_totalConnections': 1 }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$set': { 'general_timeline.' + timestamp.strftime('%d/%b/%Y %H:%M:%S'): inputLine['url']}})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_url.' + urlWithoutQuery + '.counter': 1 }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_request.' + inputLine['requestUrl'].replace('.', '_') + '.counter': 1 }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_agent.' + inputLine['uagent'].replace('.', '_') + '.counter': 1 }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$set': { 'metric_agent.' + inputLine['uagent'].replace('.', '_') + '.uagentType': 'Human' if BotMongoDB.find({'agent': inputLine['uagent']}).count() == 0 else 'Bot' }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_day.' + timestamp.strftime("%A") + '.counter': 1 }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_time.' + timestamp.strftime("%H") + '.counter': 1 }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_status.' + inputLine['code'] +'.counter': 1 }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_method.' + inputLine['method'] +'.counter': 1 }})
		bulk.find({ 'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_ext.' + helper.getFileType(inputLine['requestUrl']) +'.counter': 1 }})


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
					bulk.find({'general_ip': inputLine['ip'] }).update_one({'$set': { 'metric_param.' + pKey + '.characters': chars}})
					bulk.find({'general_ip': inputLine['ip'] }).update_one({'$set': { 'metric_param.' + pKey + '.length': len(pValue)}})
					bulk.find({'general_ip': inputLine['ip'] }).update_one({'$set': { 'metric_param.' + pKey + '.type': paramType}})
					bulk.find({'general_ip': inputLine['ip'] }).update_one({'$inc': { 'metric_param.' + pKey + '.' + pValue + '.counter': 1}})

		#### Execute bulk statement ####
		try:
			bulk.execute()
		except Exception as e:
			print e.details


		#### Setup timeline ####
		timelineDict = OutputMongoDB.find_one({'general_ip' : inputLine['ip']})['general_timeline']
		timelineList = map(list, OrderedDict(sorted(timelineDict.items(), key=lambda t: datetime.datetime.strptime(t[0], '%d/%b/%Y %H:%M:%S'))).items())

		for event in timelineList:
			#### Calculate avg time spent for each base url ####
			if timelineList.index(event) == len(timelineList) - 1:
				break

			time1 = datetime.datetime.strptime(event[0], '%d/%b/%Y %H:%M:%S')
			time2 = datetime.datetime.strptime(timelineList[timelineList.index(event)+1][0], '%d/%b/%Y %H:%M:%S')

			delta = time2 - time1

			if delta.total_seconds() > 5 and delta.total_seconds() < 3600:
				counter = OutputMongoDB.find_one({ 'general_ip' : inputLine['ip'] })['metric_url'][urlWithoutQuery]['counter']
				try:
					orgAvg = OutputMongoDB.find_one({ 'general_ip' : inputLine['ip'] })['metric_timespent'][urlWithoutQuery]
					newAvg = orgAvg + ((delta.total_seconds() - orgAvg) / counter)
				except KeyError:
					newAvg = delta.total_seconds()
				finally:
					OutputMongoDB.update_one({ 'general_ip' : inputLine['ip'] }, { '$set' : {'metric_timespent.' + urlWithoutQuery : int(newAvg)}})


		#### Calculate ratios ####
		helper.calculateRatio('general_ip', inputLine['ip'], 'metric_agent', OutputMongoDB)
		helper.calculateRatio('general_ip', inputLine['ip'], 'metric_time', OutputMongoDB)
		helper.calculateRatio('general_ip', inputLine['ip'], 'metric_day', OutputMongoDB)
		helper.calculateRatio('general_ip', inputLine['ip'], 'metric_url', OutputMongoDB)
		helper.calculateRatio('general_ip', inputLine['ip'], 'metric_request', OutputMongoDB)
		helper.calculateRatio('general_ip', inputLine['ip'], 'metric_status', OutputMongoDB)
		helper.calculateRatio('general_ip', inputLine['ip'], 'metric_method', OutputMongoDB)
		helper.calculateRatio('general_ip', inputLine['ip'], 'metric_ext', OutputMongoDB)


		#### Update progress ####
		converted += 1

	global activeWorkers
	activeWorkers -= 1

	if options.debug:
		print '[DEBUG] Worker started:'
		print '[DEBUG] Active workers: {}'.format(activeWorkers)
		print '[DEBUG] Lines processed: {}'.format(index)
		print '[DEBUG] Lines / seconds: {}'.format(index / ((datetime.datetime.now() - startTime).total_seconds()))


#### Prepare workload and send to worker ####
threads, progress = [], []
startRange = int(options.startIndex)
endRange = int(options.linesPerThread)
intLinesPerThread = int(options.linesPerThread)
loops = int(math.ceil(float(diffLines)/float(intLinesPerThread)))


for index in xrange(0, loops):

	#### Hold until worker is free ####
	while str(activeWorkers) == str(options.threads):
		pass

	#### Start of worker ####
	activeWorkers += 1
	t = threading.Thread(target=processLine, args=(startRange, index,))
	threads.append(t)
	t.start()

	#### Set range for next thread ####
	startRange += intLinesPerThread

#### Wait for all workers to finish ####
for thread in threads:
	thread.join()

progressBarObj.finish()

#### Print statistics ####
print('Total execution time: {} seconds'.format((datetime.datetime.now() - startTime).total_seconds()))
print('Average lines per second: {} l/s'.format(int(diffLines / (datetime.datetime.now() - startTime).total_seconds())))
# TODO: More statistics