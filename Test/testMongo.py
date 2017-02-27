from pymongo import MongoClient
import ast, json


#MongoDB = MongoClient().FormattedLogs['Profiler\input\FormattedBigLog.txt - 17_2_36']
MongoDB = MongoClient().WAF['13_56_54_Profile']


 
# test = list()
# index = 0;
# for mongo in MongoDB.find():
# 	MongoDB.createIndex({index:1})

# i = 0
# for x in MongoDB.find():
# 	MongoDB.update({"_id": x["_id"]}, {"$set": {"index": i}})
# 	i += 1


# MongoDB.create_index("index")



for x in MongoDB.find():
	

