import datetime, progressbar, threading
from pymongo import MongoClient
from optparse import OptionParser
from formattedLine import FormattedLine


#### Init options ####
parser = OptionParser()
parser.add_option("-l", "--log", action="store", dest="log", default="log.txt", help="Input log file for profiler")
parser.add_option("-f", "--format", action="store", dest="format", default="combined", help="Format of the input log")
parser.add_option("-t", "--threads", action="store", dest="threads", default="12", help="Amout of threats that can be used")
<<<<<<< HEAD
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="250", help="Max lines per thread")
=======
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="150", help="Max lines per thread")
>>>>>>> 3f165a3b8ea8155c5c09621d8c62f55e29dfeed1
options, args = parser.parse_args()
######################


#### Init ####
initTime = str(datetime.datetime.now().hour) + "_" +  str(datetime.datetime.now().minute) + "_" +  str(datetime.datetime.now().second)
MongoDB = MongoClient().FormattedLogs[options.log + ' - ' + initTime]
startTime = datetime.datetime.now()
##############


#### Determening lines ####
with open(options.log) as f:
	num_lines = sum(1 for line in f)
###########################


#### Preparing progress bar ####
progressBarObj = progressbar.ProgressBar(maxval=num_lines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
progressBarObj.start()
################################

inputFormat = options.format.split(' ')
inputFormat = [x.strip() for x in inputFormat]

activeWorkers = 0


def formatLine(lines, index):
	""" Format lines into unified object """

	for line in lines:
		try:
<<<<<<< HEAD
=======
			pass
		
>>>>>>> 3f165a3b8ea8155c5c09621d8c62f55e29dfeed1
			cleandedLine = filter(None, [x.strip() for x in line.split('"')])

			ip = cleandedLine[0].split(' ')[0]
			timestamp = cleandedLine[0].split(' ')[3]


			method = cleandedLine[1].split(' ')[0]
			requestUrl = cleandedLine[1].split(' ')[1]


			code = cleandedLine[2].split(' ')[0]
			size = cleandedLine[2].split(' ')[1]

			url = cleandedLine[3]
			uagent = cleandedLine[4]

			lineObj = FormattedLine(index, ip, timestamp, method, requestUrl, code, size, url, uagent)
			MongoDB.insert_one(lineObj.__dict__)
			index += 1

<<<<<<< HEAD
		except Exception:
=======
		except Exception as e:
>>>>>>> 3f165a3b8ea8155c5c09621d8c62f55e29dfeed1
			pass

	global activeWorkers
	activeWorkers -= 1
	


lines = list()
threads = []
i = 0
with open(options.log) as fileobject:
	for index, line in enumerate(fileobject, 1):

		lines.append(line)
		if index % int(float(options.linesPerThread)) == 0 or index == num_lines:

			while str(activeWorkers) == str(options.threads):
				pass

			activeWorkers += 1
			t = threading.Thread(target=formatLine, args=(lines,i,))
			i += int(options.linesPerThread)
			threads.append(t)
			t.start()

			lines = list()

		progressBarObj.update(index)

MongoDB.create_index("index")

for thread in threads:
	thread.join()

progressBarObj.finish()

print("Total execution time: {} seconds".format((datetime.datetime.now() - startTime).total_seconds()))