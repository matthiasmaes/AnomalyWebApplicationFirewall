# Public classes
import json
import progressbar
import datetime
import sys
import threading
import calendar
from pymongo import MongoClient
from optparse import OptionParser

from record import Record
from connection import Connection


#### Init global vars ####
initTime = str(datetime.datetime.now().hour) + "_" +  str(datetime.datetime.now().minute) + "_" +  str(datetime.datetime.now().second)
startTime = datetime.datetime.now()
converted, activeWorkers = 0, 0
##########################


#### Init options ####
parser = OptionParser()
parser.add_option("-p", "--ping", action="store_true", dest="ping", default=False, help="Try to resolve originating domains to ip for geolocation")
parser.add_option("-b", "--bot", action="store_true", dest="bot", default=False, help="Filter search engine bots")
parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="Show debug messages")
parser.add_option("-t", "--threads", action="store", dest="threads", default="8", help="Amout of threats that can be used")
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="250", help="Max lines per thread")
parser.add_option("-m", "--mongo", action="store", dest="inputMongo", default="testCase", help="Input via mongo")
options, args = parser.parse_args()
######################


#### Init output ####
newpath = "output/" + initTime
outputProfilePath = "output/" + initTime + "/profile.txt"
outputActivityPath = "output/" + initTime + "/activity.txt"
#####################


#### Init DB ####
OutputMongoDB = MongoClient().WAF[initTime + '_Profile']
InputMongoDB = MongoClient().FormattedLogs[options.inputMongo]
#################


#### Determening lines ####
num_lines = InputMongoDB.count()
###########################


#### Reading bot file ####
if options.bot:
	with open('input/bots.txt') as f:
		bots = f.readlines()
	bots = [x.strip() for x in bots]
##########################


#### Preparing progress bar ####
bar = progressbar.ProgressBar(maxval=num_lines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
bar.start()
################################


def processLine(records, index):
	
	for inputLine in records:

		splittedTime = (inputLine['timestamp'].replace('[', '').replace('/', ':').split(':'))
		connectionTime = splittedTime[3]
		connectionDay = (datetime.datetime(int(splittedTime[2]), int(list(calendar.month_abbr).index(splittedTime[1])), int(splittedTime[0]))).weekday()

		#### Add document on first occurance  ####
		if OutputMongoDB.find({"url": inputLine['url'] }).count() == 0:
			OutputMongoDB.insert_one((Record(inputLine['method'], inputLine['url'], inputLine['code'], inputLine['size'])).__dict__)
		##########################################

		#### Add Connection to db ####

		accessedBy = ''

		if options.bot:
			if next((True for bot in bots if inputLine['uagent'] in bot), False):
				accessedBy = 'Bot'
			else:
				accessedBy = 'Human'
		else:
			accessedBy = 'Bot filtering disabled use: --bot'

		OutputMongoDB.update({"url": inputLine['url'] }, {'$push': {'connection': Connection(inputLine['ip'], connectionTime, connectionDay, options.ping, accessedBy, inputLine['requestUrl']).__dict__}})

		##############################


		#### Update progress ####
		global converted
		converted += 1

		if not options.debug:
			bar.update(converted)
		#########################


		global activeWorkers
	activeWorkers -= 1

	if options.debug:
		print "[DEBUG] Worker started:"
		print "[DEBUG] Active workers: {}".format(activeWorkers)
		print "[DEBUG] Lines processed: {}".format(index)
		print '[DEBUG] Lines / seconds: {}'.format(index / ((datetime.datetime.now() - startTime).total_seconds()))

		
#### Prepare workload and send to worker ####
threads, progress = [], []
startRange = 0
endRange = int(options.linesPerThread)

results = InputMongoDB.find()

for index, line in enumerate(results, 1):

	if index == num_lines or index % int(options.linesPerThread):

		#### Hold until worker is free ####
		while str(activeWorkers) == str(options.threads):
			pass
		###################################


		#### Start of worker ####
		activeWorkers += 1
		t = threading.Thread(target=processLine, args=(InputMongoDB.find()[startRange:endRange], index,))
		threads.append(t)
		t.start()
		#########################

		startRange = endRange
		endRange += int(options.linesPerThread)

############################################


#### Wait for all workers to finish ####
for thread in threads:
	thread.join()
########################################

bar.finish()

#### Print statistics ####
print("Total execution time: {} seconds".format((datetime.datetime.now() - startTime).total_seconds()))
print("Average lines per second: {} l/s".format(int(num_lines / (datetime.datetime.now() - startTime).total_seconds())))
# TODO: More statistics
##########################