import progressbar, string
import datetime
import threading
import math
import IP2Location
import dns.resolver
import helper
from pymongo import MongoClient
from optparse import OptionParser
from record_app import Record_App


#### Init global vars ####
initTime = str('%02d' % datetime.datetime.now().hour) + ':' +  str('%02d' % datetime.datetime.now().minute) + ':' +  str('%02d' % datetime.datetime.now().second)
startTime = datetime.datetime.now()
converted, activeWorkers = 0, 0


#### Init options ####
options, args = helper.setupParser()


#### Init DB ####
OutputMongoDB = MongoClient().profile_app['profile_app_' + initTime]
InputMongoDB = MongoClient().FormattedLogs[options.inputMongo]
BotMongoDB = MongoClient().config_static.profile_bots


#### Place index on url field to speed up searches through db ####
# OutputMongoDB.create_index('_id', background=True)


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


		timestamp = datetime.datetime.strptime(inputLine['fulltime'].split(' ')[0], '%d/%b/%Y:%H:%M:%S')
		urlWithoutQuery = helper.getUrlWithoutQuery(inputLine['url'])
		queryString = [element.replace('.', '_') for element in helper.getQueryString(inputLine['url'])]

		if 'admin' in urlWithoutQuery.lower() or 'administrator' in urlWithoutQuery.lower():
			print 'Admin'


		#### Add document on first occurance  ####
		if OutputMongoDB.find({'_id': urlWithoutQuery}).count() == 0:
			OutputMongoDB.insert_one({'_id': urlWithoutQuery})



		#### FIRST BULK ####
		bulk = OutputMongoDB.initialize_ordered_bulk_op()
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'general_totalConnections': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$set': { 'general_timeline.' + timestamp.strftime('%d/%b/%Y %H:%M:%S'): inputLine['ip']}})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_day.' + timestamp.strftime("%A") + '.counter': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_time.' + timestamp.strftime("%H") + '.counter': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_agent.' + inputLine['uagent'].replace('.', '_') + '.counter': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$set': { 'metric_agent.' + inputLine['uagent'].replace('.', '_') + '.uagentType': 'Human' if BotMongoDB.find({'agent': inputLine['uagent']}).count() == 0 else 'Bot' }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_request.' + inputLine['requestUrl'].replace('.', '_') + '.counter': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_ext.' + helper.getFileType(inputLine['requestUrl']) +'.counter': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_status.' + inputLine['code'] +'.counter': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_method.' + inputLine['method'] +'.counter': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_geo.' + helper.GeoLocate(inputLine['ip'], options.ping) + '.counter': 1 }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_conn.' + inputLine['ip'].replace('.', '_') + '.counter': 1 }})


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
					bulk.find({'_id': urlWithoutQuery }).update_one({'$set': { 'metric_param.' + pKey + '.characters': chars}})
					bulk.find({'_id': urlWithoutQuery }).update_one({'$set': { 'metric_param.' + pKey + '.type': paramType}})
					bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_param.' + pKey + '.' + pValue + '.counter': 1}})
					bulk.find({'_id': urlWithoutQuery }).update_one({'$inc': { 'metric_param.' + pKey + '.counter': 1}})



		#### Execute batch ####
		try:
			bulk.execute()
		except Exception:
			pass




		#### SECOND BULK ####
		bulk = OutputMongoDB.initialize_unordered_bulk_op()

		bulk.find({'_id': urlWithoutQuery }).update_one({'$set': { 'metric_unique.counter': len(OutputMongoDB.find_one({'_id': urlWithoutQuery})['metric_conn']) }})
		bulk.find({'_id': urlWithoutQuery }).update_one({'$set': { 'metric_unique.ratio': float(len(OutputMongoDB.find_one({'_id': urlWithoutQuery})['metric_conn'])) / float(OutputMongoDB.find_one({'_id': urlWithoutQuery})['general_totalConnections']) }})

		try:
			bulk.execute()
		except Exception:
			pass


		#### Setup timeline ####
		helper.makeTimeline(OutputMongoDB,  urlWithoutQuery, inputLine['ip'].replace('.', '_'))

		#### Calculate ratio for metrics ####
		helper.calculateRatio('_id', urlWithoutQuery, 'metric_geo', OutputMongoDB)
		helper.calculateRatio('_id', urlWithoutQuery, 'metric_agent', OutputMongoDB)
		helper.calculateRatio('_id', urlWithoutQuery, 'metric_time', OutputMongoDB)
		helper.calculateRatio('_id', urlWithoutQuery, 'metric_day', OutputMongoDB)
		helper.calculateRatio('_id', urlWithoutQuery, 'metric_ext', OutputMongoDB)
		helper.calculateRatio('_id', urlWithoutQuery, 'metric_request', OutputMongoDB)
		helper.calculateRatio('_id', urlWithoutQuery, 'metric_status', OutputMongoDB)
		helper.calculateRatio('_id', urlWithoutQuery, 'metric_method', OutputMongoDB)


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
loops = int(math.ceil(float(diffLines) / float(intLinesPerThread)))


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