from pymongo import MongoClient
import ast, json


#MongoDB = MongoClient().FormattedLogs['Profiler\input\FormattedBigLog.txt - 17_2_36']
MongoDB = MongoClient().FormattedLogs['Profiler\input\FormattedBigLog.min.txt - 10_29_52']


 
# test = list()
# index = 0;
# for mongo in MongoDB.find():
# 	MongoDB.createIndex({index:1})


print MongoDB.find_one({'index': 69})


