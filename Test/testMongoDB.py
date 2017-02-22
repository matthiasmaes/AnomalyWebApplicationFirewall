from pymongo import MongoClient


import datetime


client = 
collection = MongoClient().Test.testCol



post = {"author": "Mike",
		"text": "My first blog post!",
		"tags": ["mongodb", "python", "pymongo"],
		"date": datetime.datetime.utcnow()}

collection.insert_one(post)



print collection.find_one()