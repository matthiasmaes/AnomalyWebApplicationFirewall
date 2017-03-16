from pymongo import MongoClient
import random

StreamMongoDB = MongoClient().Firewall.TestStream
InputMongoDB = MongoClient().FormattedLogs.DEMO

setPackets = list(InputMongoDB.find()[0:4])


while True:
	randomPacket = InputMongoDB.find()[random.randint(1, 10)]

	print 'Constant requests'

	counter = 1
	for packet in setPackets:
		print '[{}] REQUEST INFO: url: {}, time: {}, date: {}'.format(counter, packet['url'], packet['fulltime'], packet['date'])
		counter += 1

	print ''
	print 'Random requests'
	print '[{}] REQUEST INFO: url: {}, time: {}, date: {}'.format(counter, randomPacket['url'], randomPacket['fulltime'], randomPacket['date'])
	print ''

	userInput = raw_input('Make your choice: ')

	if int(userInput) >= 1 and int(userInput) <= 4:
		StreamMongoDB.insert_one(setPackets[int(userInput) - 1])
	else:
		StreamMongoDB.insert_one(setPackets[5])