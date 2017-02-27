# Public classes
import re
import string
import json
import requests
import sys
import progressbar
import IP2Location
import datetime
import os
import threading
from pymongo import MongoClient
from optparse import OptionParser

# Private classes
import logFile
import record
from connection import Connection


#### Init global vars ####
tmpStorage = []
activityDictionary = {}
initTime =  str(datetime.datetime.now().hour) + "_" +  str(datetime.datetime.now().minute) + "_" +  str(datetime.datetime.now().second)
startTime = datetime.datetime.now()
##########################


#### Init options ####
parser = OptionParser()
parser.add_option("-p", "--ping", action="store_true", dest="ping", default=False, help="Try to resolve originating domains to ip for geolocation")
parser.add_option("-l", "--log", action="store", dest="log", default="input/log.txt", help="Input log file for profiler")
parser.add_option("-t", "--threads", action="store", dest="threads", default="2", help="Amout of threats that can be used")
options, args = parser.parse_args()
######################


#### Init input ####
inputFileObj = logFile.LogFile(options.log);
####################


#### Init output ####
newpath = "output/" + initTime
outputProfilePath = "output/" + initTime + "/profile.txt"
outputActivityPath = "output/" + initTime + "/activity.txt"
#####################


#### Init DB ####
MongoDB = MongoClient().WAF[initTime + '_Profile']
#################


#### Determening lines ####
with open(options.log) as f:
	num_lines = sum(1 for line in f)
linesPerThread = num_lines / int(options.threads)
###########################


#### Preparing progress bar ####
bar = progressbar.ProgressBar(maxval=num_lines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
bar.start()
################################


def processLine(lines, activeWorkers):
	for line in lines:
		splittedLineFromLog = line.replace('\"', '').replace('\n','').split(' ')
		newRecord = record.Record(splittedLineFromLog[5], splittedLineFromLog[6], splittedLineFromLog[8], splittedLineFromLog[9])
		connectionTime = (splittedLineFromLog[3].replace('[', '').replace('/', ':').split(':'))[3]


		#### If record already exists add a connection ####
		if MongoDB.find({"url": newRecord.getURL()}).count() == 0:

			#### Connection obj -> dict ####
			tmpJSON = []
			for connection in newRecord.connection:
				tmpJSON.append(connection.__dict__)
			newRecord.connection = tmpJSON
			################################


			#### Save to MongoDB ####
			MongoDB.insert_one(newRecord.__dict__)
			#########################
			
		###################################################


		#### Add Connection to db ####	
		MongoDB.update({"url": newRecord.getURL()}, {'$push': {'connection': Connection(splittedLineFromLog[0], connectionTime, options.ping).__dict__}})
		##############################

		progress[activeWorkers] +=1
		



def reporter():
	totalProgress = 0
	for pro in progress:
		totalProgress += pro
	bar.update(totalProgress)





#### worker assignment ####
threads = []
progress = []
lines = list()
activeWorkers = 0
with open(options.log) as fileobject:
	for index, line in enumerate(fileobject, 1):
		lines.append(line)

		if int(options.threads) - 1 ==  activeWorkers:			
				if index == num_lines:
					t = threading.Thread(target=processLine, args=(lines,activeWorkers,))
					threads.append(t)
					progress.append(0)
					t.start()

		elif index % linesPerThread == 0:
				t = threading.Thread(target=processLine, args=(lines,activeWorkers,))
				threads.append(t)
				progress.append(0)
				t.start()

				activeWorkers += 1
				lines = list()
###########################






#### wait for all threads to finish ####
for thread in threads:
	while thread.isAlive() :
		reporter()
########################################


#### Print statistics ####
print("Total execution time: {} seconds".format((datetime.datetime.now() - startTime).total_seconds()))
# TODO: More statistics
##########################


bar.finish()