import datetime, progressbar, threading
from pymongo import MongoClient
from optparse import OptionParser




import sys
sys.path.append('C:/Users/bebxadvmmae/Desktop/REMOTE/0. Helper')
from formattedLine import FormattedLine
from helper import Helper, TYPE, SCRIPT

#### Init helper object ####
helperObj = Helper()


#### Init options ####
parser = OptionParser()
parser.add_option("-l", "--log", action="store", dest="log", default="access.log", help="Input log file for profiler")
parser.add_option("-f", "--format", action="store", dest="format", default="combined", help="Format of the input log")
parser.add_option("-t", "--threads", action="store", dest="threads", default="12", help="Amout of threats that can be used")
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="100", help="Max lines per thread")
parser.add_option("-p", "--procent", action="store", dest="procentToParse", default="100", help="Set how much of the logfile to parse")
parser.add_option("-s", "--start", action="store", dest="startToParse", default="0", help="Set line number to start parsing from")
parser.add_option("-d", "--db", action="store", dest="dbName", default="", help="Set collection to add parsed lines")
options, args = parser.parse_args()
######################


#### Init ####
initTime = str('%02d' % datetime.datetime.now().hour) + ":" +  str('%02d' % datetime.datetime.now().minute) + ":" +  str('%02d' % datetime.datetime.now().second)
MongoDB = MongoClient().FormattedLogs[options.dbName if options.dbName is not "" else options.log + ' - ' + initTime]
startTime = datetime.datetime.now()
MongoDB.create_index('index', background=True)
##############



#### Determining amount of lines ####
with open(options.log) as f:
	num_lines = sum(1 for line in f)
linesToProcess = (num_lines * int(options.procentToParse)) / 100

#### Determining start and end ####
startIndex = int(options.startToParse)
endIndex = num_lines if startIndex + linesToProcess > num_lines else startIndex + linesToProcess
print 'Lines from {} till {} will be processed'.format(startIndex, endIndex)

#### Preparing progress bar ####
progressBarObj = progressbar.ProgressBar(maxval=endIndex, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
progressBarObj.start()

activeWorkers = 0

def formatLine(lines, index):
	""" Format lines into unified object """

	for line in lines:
		try:
			MongoDB.insert_one(helperObj.processLine(line, index))
		except Exception as e:
			print 'Following error occured: {} on line {}'.format(line, e)
			print e

	global activeWorkers
	activeWorkers -= 1



#### Spread workload among workers ####
lines = list()
threads = []
i = 0
with open(options.log) as fileobject:
	for index, line in enumerate(fileobject, startIndex):

		print line
		lines.append(line)

		#### If lines reach max per thread or eof a worker is started ####
		if index % int(float(options.linesPerThread)) == 0 or index >= num_lines or index >= endIndex:

			#### Wait for a free worker ####
			while str(activeWorkers) == str(options.threads):
				pass

			#### Start a new worker ####
			activeWorkers += 1
			t = threading.Thread(target=formatLine, args=(lines,i,))
			i += int(options.linesPerThread)
			threads.append(t)
			t.start()

			#### Clear the list after assignment ####
			lines = list()

			if index == endIndex:
				break

		progressBarObj.update(index)


#### Wait for all threads to finish ####
for thread in threads:
	thread.join()

#### Finish script ####
progressBarObj.finish()
print("Total execution time: {} seconds".format((datetime.datetime.now() - startTime).total_seconds()))
print("Average lines per second: {} l/s".format(int((endIndex - startIndex) / (datetime.datetime.now() - startTime).total_seconds())))

#### Info to process rest of file ####
if int(options.startToParse) is not 0 or int(options.procentToParse) is not 100:
	print 'Next parse should start from index: {}. Use -s {}'.format(endIndex + 1, endIndex + 1)