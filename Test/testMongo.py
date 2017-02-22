from pymongo import MongoClient
import ast, json


MongoDB = MongoClient().FormattedLogs['test']


print MongoDB.find()[0]['method']