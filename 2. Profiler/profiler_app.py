import progressbar, string
import datetime
import threading
import math
import IP2Location
import dns.resolver
from helper import Helper
from pymongo import MongoClient
from optparse import OptionParser


#### Init global vars ####
initTime = str('%02d' % datetime.datetime.now().hour) + ':' +  str('%02d' % datetime.datetime.now().minute) + ':' +  str('%02d' % datetime.datetime.now().second)
startTime = datetime.datetime.now()
converted, activeWorkers = 0, 0

#### Init helper object ####
helperObj = Helper()

#### Init options ####
options, args = helperObj.setupParser()

#### Init DB ####
InputMongoDB = MongoClient().FormattedLogs[options.inputMongo]
helperObj.OutputMongoDB = MongoClient().profile_app['profile_app_' + initTime]
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

#### Determening lines to process####
options.endindex = InputMongoDB.count() if int(options.endindex) == 0 else int(options.endindex)
diffLines = int(options.endindex) - int(options.startIndex) + 1

#### Preparing progress bar ####
progressBarObj = progressbar.ProgressBar(maxval=diffLines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
progressBarObj.start()

class TYPE:
	USER, APP = range(2)

class SCRIPT:
	PROFILER, FIREWALL = range(2)


def processLine(start, index):
	""" Assign workers with workload """

	global converted

	for inputLine in InputMongoDB.find()[start : start + int(options.linesPerThread)]:

		if converted >= diffLines:
			print 'break on: ' + str(converted)
			break
		else:
			progressBarObj.update(converted)
			helperObj.processLineCombined(TYPE.APP, SCRIPT.PROFILER, inputLine, options)

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

try:
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

except Exception as e:
	raise e

except KeyboardInterrupt:
	print 'Script cancelled by user'

finally:
	progressBarObj.finish()
	for thread in threads:
		thread.join()

	#### Print statistics ####
	print('Total execution time: {} seconds'.format((datetime.datetime.now() - startTime).total_seconds()))
	print('Average lines per second: {} l/s'.format(int(diffLines / (datetime.datetime.now() - startTime).total_seconds())))