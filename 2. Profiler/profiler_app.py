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
initTime = str('%02d' % datetime.datetime.now().hour) + ":" +  str('%02d' % datetime.datetime.now().minute) + ":" +  str('%02d' % datetime.datetime.now().second)
startTime = datetime.datetime.now()
converted, activeWorkers = 0, 0


#### Init options ####
options, args = helper.setupParser()


#### Init DB ####
OutputMongoDB = MongoClient().profile_app['profile_app_' + initTime]
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



def calculateRatioParam(url, pKey):
	""" Method for calculating the ratio for a given metric """

	currRecord = OutputMongoDB.find_one({'url': url })

	for param in currRecord['metric_param'][pKey]:
		try:
			#### Update ratio on all affected records and metrics (if counter changes on one metric, ratio on all has to be updated) ####
			OutputMongoDB.update({'url': url}, {'$set': { 'metric_param' + '.' + pKey + '.' + param + '.ratio': float(currRecord['metric_param'][pKey][param]['counter']) / float(currRecord['metric_param'][pKey]['counter'])}})
		except TypeError:
			#### Not every metric has a counter/ratio field, this will be catched by the TypeError exception ####
			pass



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


		urlWithoutPoints = inputLine['requestUrl'].replace('.', '_')
		timestamp = datetime.datetime.strptime( inputLine['fulltime'].split(' ')[0], '%d/%b/%Y:%H:%M:%S')
		urlWithoutQuery = helper.getUrlWithoutQuery(inputLine['url'])
		queryString = [element.replace('.', '_') for element in helper.getQueryString(inputLine['url'])]
		userAgent_Replaced = inputLine['uagent'].replace('.', '_')


		#### Determine file extension ####
		try:
			filetype = inputLine['requestUrl'].split('.')[1].split('?')[0]
		except Exception:
			try:
				filetype = inputLine['requestUrl'].split('.')[1]
			except Exception:
				filetype = 'url'


		#### Add document on first occurance  ####
		if OutputMongoDB.find({'url': urlWithoutQuery}).count() == 0:
			OutputMongoDB.insert_one((Record_App(inputLine['method'], urlWithoutQuery)).__dict__)


		#### Batch update all metrics ####
		bulk = OutputMongoDB.initialize_ordered_bulk_op()
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'general_totalConnections': 1 }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_day.' + timestamp.strftime("%A") + '.counter': 1 }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_time.' + timestamp.strftime("%H") + '.counter': 1 }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_geo.' + helper.GeoLocate(inputLine['ip'], options.ping) + '.counter': 1 }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_agent.' + userAgent_Replaced + '.counter': 1 }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$set': { 'metric_agent.' + userAgent_Replaced + '.uagentType': 'Human' if BotMongoDB.find({'agent': inputLine['uagent']}).count() == 0 else 'Bot' }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_request.' + urlWithoutPoints + '.counter': 1 }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_ext.' + filetype +'.counter': 1 }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_status.' + inputLine['code'] +'.counter': 1 }})
		bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_method.' + inputLine['method'] +'.counter': 1 }})



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
					bulk.find({'url': urlWithoutQuery }).update_one({'$set': { 'metric_param.' + pKey + '.characters': chars}})
					bulk.find({'url': urlWithoutQuery }).update_one({'$set': { 'metric_param.' + pKey + '.type': paramType}})
					bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_param.' + pKey + '.' + pValue + '.counter': 1}})
					bulk.find({'url': urlWithoutQuery }).update_one({'$inc': { 'metric_param.' + pKey + '.counter': 1}})


		#### Execute batch ####
		try:
			bulk.execute()
		except Exception:
			pass


		#### Calculate ratio for metrics ####
		helper.calculateRatio('url', urlWithoutQuery, 'metric_geo', OutputMongoDB)
		helper.calculateRatio('url', urlWithoutQuery, 'metric_agent', OutputMongoDB)
		helper.calculateRatio('url', urlWithoutQuery, 'metric_time', OutputMongoDB)
		helper.calculateRatio('url', urlWithoutQuery, 'metric_day', OutputMongoDB)
		helper.calculateRatio('url', urlWithoutQuery, 'metric_ext', OutputMongoDB)
		helper.calculateRatio('url', urlWithoutQuery, 'metric_request', OutputMongoDB)
		helper.calculateRatio('url', urlWithoutQuery, 'metric_status', OutputMongoDB)
		helper.calculateRatio('url', urlWithoutQuery, 'metric_method', OutputMongoDB)


		if len(queryString) > 0:
			for param in queryString:
				if len(param.split('=')) == 2:

					pKey = param.split('=')[0]
					pValue = '-' if not param.split('=')[1] else param.split('=')[1]

					calculateRatioParam(urlWithoutQuery, pKey)

					try:
						orgAvg = OutputMongoDB.find_one({'url': urlWithoutQuery})['metric_param'][pKey]
						newAvg = orgAvg['length'] + ((len(pValue) - orgAvg['length']) / orgAvg['counter'])
					except KeyError:
						newAvg = len(pValue)
					finally:
						OutputMongoDB.update_one({'url': urlWithoutQuery} , {'$set': { 'metric_param.' + pKey + '.length': newAvg}})


		#### Update progress ####
		converted += 1

	global activeWorkers
	activeWorkers -= 1

	if options.debug:
		print "[DEBUG] Worker started:"
		print "[DEBUG] Active workers: {}".format(activeWorkers)
		print "[DEBUG] Lines processed: {}".format(index)
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
print("Total execution time: {} seconds".format((datetime.datetime.now() - startTime).total_seconds()))
print("Average lines per second: {} l/s".format(int(diffLines / (datetime.datetime.now() - startTime).total_seconds())))
# TODO: More statistics