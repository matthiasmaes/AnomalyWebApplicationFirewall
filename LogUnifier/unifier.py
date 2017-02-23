import json, datetime, progressbar, threading
from pymongo import MongoClient
from optparse import OptionParser
from formattedLine import FormattedLine


#### Init options ####
parser = OptionParser()
parser.add_option("-l", "--log", action="store", dest="log", default="log.txt", help="Input log file for profiler")
parser.add_option("-f", "--format", action="store", dest="format", default="%h %l %u %t %r %>s %b %U %{User-Agent}i", help="Format of the input log")
parser.add_option("-t", "--threads", action="store", dest="threads", default="8", help="Amout of threats that can be used")
parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="100", help="Max lines per thread")
options, args = parser.parse_args()
######################


#### Init ####
initTime = str(datetime.datetime.now().hour) + "_" +  str(datetime.datetime.now().minute) + "_" +  str(datetime.datetime.now().second)
MongoDB = MongoClient().FormattedLogs[options.log + ' - ' + initTime]
##############


#### Determening lines ####
with open(options.log) as f:
	num_lines = sum(1 for line in f)
###########################


#### Preparing progress bar ####
bar = progressbar.ProgressBar(maxval=num_lines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
bar.start()
################################

inputFormat = options.format.split(' ')
inputFormat = [x.strip() for x in inputFormat]

activeWorkers = 0


def formatLine(lines, index):

	for line in lines:
		cleandedLine = filter(None, [x.strip() for x in line.split('"')])
		ip = cleandedLine[inputFormat.index('%h')]
		timestamp = cleandedLine[inputFormat.index('%t')]

		
		method = cleandedLine[inputFormat.index('%r')].split(' ')[0]
		requestUrl = cleandedLine[inputFormat.index('%r')].split(' ')[1]

		code = cleandedLine[inputFormat.index('%>s')]
		size = cleandedLine[inputFormat.index('%b')]
		url = cleandedLine[inputFormat.index('%U')]
		uagent = cleandedLine[inputFormat.index('%{User-Agent}i')]
		lineObj = FormattedLine(index, ip, timestamp, method, requestUrl, code, size, url, uagent)
		MongoDB.insert_one(lineObj.__dict__)
		index += 1
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


		bar.update(index)

MongoDB.create_index("index")

for thread in threads:
	thread.join()

bar.finish()