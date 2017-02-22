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


#### Preparing progress bar ####
with open(options.log) as f:
	num_lines = sum(1 for line in f)

bar = progressbar.ProgressBar(maxval=num_lines, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
bar.start()
################################




index = 0
with open(options.log) as fileobject:
	for line in fileobject:
		splittedLineFromLog = line.replace('\"', '').replace('\n','').split(' ')
		newRecord = record.Record(splittedLineFromLog[5], splittedLineFromLog[6], splittedLineFromLog[8], splittedLineFromLog[9])
		connectionTime = (splittedLineFromLog[3].replace('[', '').replace('/', ':').split(':'))[3]

		
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


		#### Add Connection to db ####	
		MongoDB.update({"url": newRecord.getURL()}, {'$push': {'connection': Connection(splittedLineFromLog[0], connectionTime, options.ping).__dict__}})
		##############################


		index += 1
		bar.update(index)
bar.finish()


#### Print statistics ####
print("Total execution time: {} seconds".format((datetime.datetime.now() - startTime).total_seconds()))
# TODO: More statistics
##########################