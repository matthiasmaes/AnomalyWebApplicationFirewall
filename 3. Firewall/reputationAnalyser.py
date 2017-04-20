import time
from pymongo import MongoClient
import iptc
import datetime
ReputationMongoDB = MongoClient().Firewall.reputation




from crontab import CronTab




def addCronJob():
	cron = CronTab(user='root')
	job = cron.new(command='/usr/bin/python /home/testPrint.py', comment='test')
	job.minute.every(1)
	cron.write()


def blockIpTable(ip):
	table = iptc.Table(iptc.Table.FILTER)
	chain = iptc.Chain(table, "INPUT")
	rule = iptc.Rule()
	rule.src = ip
	rule.target = rule.create_target("DROP")
	rule.match = rule.create_match("comment").comment = str(datetime.datetime.strftime(datetime.datetime.now() + datetime.timedelta(minutes=1), "%y-%m-%d %H:%M:%S"))
	chain.insert_rule(rule)



if __name__ == '__main__':
	print 'Analysing started...'
	while True:
		for client in ReputationMongoDB.find({'registered': False, 'rep': { '$lt': -100 }}):
			print 'bad ip: ', client['ip']
			ReputationMongoDB.update_one({'_id': client['_id']}, {'$set' : {'registered': True, 'rep': 0}})

			blockIpTable(client['ip'])


		for x in xrange(0,10):
			print '.',
			time.sleep(1)

		print ''
