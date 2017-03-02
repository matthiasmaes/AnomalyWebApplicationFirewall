# Public classes
import progressbar
import datetime
import threading
import calendar
import math
from pymongo import MongoClient
from optparse import OptionParser

from record import Record
from connection import Connection


#### Init global vars ####
initTime = str(datetime.datetime.now().hour) + "_" +  str(datetime.datetime.now().minute) + "_" +  str(datetime.datetime.now().second)
startTime = datetime.datetime.now()
converted, activeWorkers = 0, 0
weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']


#### Init options ####
parser = OptionParser()
parser.add_option("-p", "--ping", action="store_true", dest="ping", default=False, help="Try to resolve originating domains to ip for geolocation")
parser.add_option("-b", "--bot", action="store_true", dest="bot", default=False, help="Filter search engine bots")
parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="Show debug messages")
parser.add_option("-t", "--threads", action="store", dest="threads", default="16", help="Amout of threats that can be used")
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="250", help="Max lines per thread")
parser.add_option("-m", "--mongo", action="store", dest="inputMongo", default="DEMO", help="Input via mongo")

parser.add_option("-s", "--start", action="store", dest="startIndex", default="0", help="Start index for profiling")
parser.add_option("-e", "--end", action="store", dest="endindex", default="0", help="End index for profiling")

options, args = parser.parse_args()


#### Init DB ####
OutputMongoDB = MongoClient().Profiles[initTime + '_Profile']
InputMongoDB = MongoClient().FormattedLogs[options.inputMongo]


#### Determening lines ####
options.endindex = InputMongoDB.count() if int(options.endindex) == 0 else int(options.endindex)

diffLines = int(options.endindex) - int(options.startIndex) + 1

print diffLines

#### Reading bot file ####
if options.bot:
	with open('sources/bots.txt') as f:
		bots = f.readlines()
	bots = [x.strip() for x in bots]


#### Preparing progress bar ####
progressBarObj = progressbar.ProgressBar(maxval=diffLines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
progressBarObj.start()


def processLine(start, index):
	""" Assign workers with workload """

	s = start
	e = start + int(options.linesPerThread)

	for record in InputMongoDB.find()[s:e]:

		global converted

		#### Get record based on index ####
		inputLine = record

		#### Break loop if index is not found ####
		if inputLine is None: 
			continue	

		#### End if all lines were converted ####
		if converted >= diffLines:
			print 'break on: ' + str(converted)
			break
		else:
			progressBarObj.update(converted)

		#### Format time ####
		splittedTime = inputLine['date'].split('/')
		connectionDay = weekdays[(datetime.datetime(int(splittedTime[2]), int(list(calendar.month_abbr).index(splittedTime[1])), int(splittedTime[0]))).weekday()]		

		#### Add document on first occurance  ####
		if OutputMongoDB.find({'url': inputLine['url']}).count() == 0:
			OutputMongoDB.insert_one((Record(inputLine['method'], inputLine['url'], inputLine['code'], inputLine['size'])).__dict__)		

		#### Filter accessor based on uagent ####
		accessedBy = ''
		if options.bot:
			if next((True for bot in bots if inputLine['uagent'] in bot), False):
				accessedBy = 'Bot'
			else:
				accessedBy = 'Human'
		else:
			accessedBy = 'Bot filtering disabled use: --bot'		



		connObj =  Connection(inputLine['ip'], inputLine['time'], connectionDay, options.ping, accessedBy, inputLine['requestUrl'])

		#### Init Batch ####
		bulk = OutputMongoDB.initialize_unordered_bulk_op()

		#### Add connection to url ####
		bulk.find({"url": inputLine['url'] }).update({'$push': {'connection': connObj.__dict__}})
		
		#### Add activity from connection ####
		bulk.find({"url": inputLine['url'] }).update({'$inc': { 'activity.' + connectionDay: 1 }})

		#### Add time from connection ####
		bulk.find({"url": inputLine['url'] }).update({'$inc': { 'time.' + inputLine['time']: 1 }})

		#### Add location from connection ####
		bulk.find({"url": inputLine['url'] }).update({'$inc': { 'location.' + connObj.getLocation(): 1 }})

		#### Execute batch ####
		bulk.execute()



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

#### Finishing - Cleaning ####
for x in OutputMongoDB.find():

	if len(x['connection']) == 0:
		OutputMongoDB.delete_one({'_id': x['_id']})
		continue

	for location in x['location']:
		OutputMongoDB.update({"url": x['url']} , {'$set': { 'location.' + location: (float(x['location'][location]) / float(len(x['connection']))) }})

progressBarObj.finish()

#### Print statistics ####
print("Total execution time: {} seconds".format((datetime.datetime.now() - startTime).total_seconds()))
print("Average lines per second: {} l/s".format(int(diffLines / (datetime.datetime.now() - startTime).total_seconds())))
# TODO: More statistics