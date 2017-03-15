import datetime, progressbar, threading
from pymongo import MongoClient
from optparse import OptionParser
from formattedLine import FormattedLine

#### Init options ####
parser = OptionParser()
parser.add_option("-l", "--log", action="store", dest="log", default="log.txt", help="Input log file for profiler")
parser.add_option("-f", "--format", action="store", dest="format", default="combined", help="Format of the input log")
parser.add_option("-t", "--threads", action="store", dest="threads", default="12", help="Amout of threats that can be used")
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="250", help="Max lines per thread")
parser.add_option("-p", "--procent", action="store", dest="procentToParse", default="100", help="Set how much of the logfile to parse")
parser.add_option("-s", "--start", action="store", dest="startToParse", default="0", help="Set line number to start parsing from")
parser.add_option("-d", "--db", action="store", dest="dbName", default="", help="Set collection to add parsed lines")
options, args = parser.parse_args()
######################


#### Init ####
initTime = str(datetime.datetime.now().hour) + "_" +  str(datetime.datetime.now().minute) + "_" +  str(datetime.datetime.now().second)
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

			#### Repace empyt parameters with -, in order to not confus the split ####
			cleandedLine = filter(None, [x.strip() for x in line.replace('""','"-"').split('"')])

			#### Set all required vars ####
			ip = cleandedLine[0].split(' ')[0]
			date = cleandedLine[0].split(' ')[3].split(':')[0].replace('[', '')
			time = cleandedLine[0].split(' ')[3].split(':')[1]
			timezone = cleandedLine[0].split(' ')[4].replace(']', '')
			method = cleandedLine[1].split(' ')[0]
			requestUrl = cleandedLine[1].split(' ')[1]
			code = cleandedLine[2].split(' ')[0]
			size = cleandedLine[2].split(' ')[1]
			url = cleandedLine[3]
			uagent = cleandedLine[4]

			#### Create line object and insert it in mongodb
			lineObj = FormattedLine(index, ip, date, time, timezone, method, requestUrl, code, size, url, uagent)
			MongoDB.insert_one(lineObj.__dict__)
			index += 1

		except Exception:
			#print 'Following error occured: {} on line {}'.format(line, e)
			pass

	global activeWorkers
	activeWorkers -= 1



#### Spread workload among workers ####
lines = list()
threads = []
i = 0
with open(options.log) as fileobject:
	for index, line in enumerate(fileobject, startIndex):
		lines.append(line)

		#### If lines reach max per thread or eof a worker is started ####
		if index % int(float(options.linesPerThread)) == 0 or index == num_lines or index == endIndex:

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