
import time
from pymongo import MongoClient

ReputationMongoDB = MongoClient().Firewall.reputation

if __name__ == '__main__':
	print 'Analysing started...'
	while True:
		for client in ReputationMongoDB.find({'registered': False, 'rep': { '$lt': -10 }}):
			print 'bad ip: ', client['ip']
			ReputationMongoDB.update_one({'_id': client['_id']}, {'$set' : {'registered': True, 'rep': 0}})


		for x in xrange(0,10):
			print '.',
			time.sleep(1)

		print ''



		