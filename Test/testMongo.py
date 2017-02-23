from pymongo import MongoClient
import ast, json


MongoDB = MongoClient().FormattedLogs['Profiler\input\FormattedBigLog.txt - 17_2_36']


 

for mongo in MongoDB.find()[0:1]:
	print mongo



