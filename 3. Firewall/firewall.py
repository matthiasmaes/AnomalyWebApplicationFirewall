from pymongo import MongoClient
import IP2Location


ConfigMongoDB = MongoClient().Firewall.StaticConfig
StreamMongoDB = MongoClient().Firewall.TestStream
TmpMongoDB = MongoClient().Firewall.tmp
ProfileMongoDB = MongoClient().Profiles['13_13_15_Profile']



for packet in StreamMongoDB.find():



	#### Geo locate ip address ####
	IP2LocObj = IP2Location.IP2Location();
	IP2LocObj.open('C:/Users/bebxadvmmae/Desktop/REMOTE/2. Profiler/sources/IP2GEODB.BIN');
	GeoQuery = IP2LocObj.get_all(packet['ip']).country_long;



	#### Check for geolocation ####
	if ConfigMongoDB.find({'Category': 'Location', 'Data': GeoQuery}).count() > 0:

		#### If location is in black list take appropriate action ####
		if (ConfigMongoDB.find_one({'Category': 'Location', 'Data': GeoQuery}))['Action'] == 'Alert' :
			print '[ALERT] Connection made from blacklisted country'

	elif GeoQuery not in (ProfileMongoDB.find_one({ 'url' : packet['url'] }))['location']:

		#### Keep counter on unknown locations ####
		if TmpMongoDB.find({'Location': GeoQuery}).count() == 0:
			TmpMongoDB.insert_one({'Location': GeoQuery, 'Occurance' : 0})
		TmpMongoDB.update({'Location': GeoQuery}, {'$inc': { 'Occurance' : 1 }})


		#### If connections counter exceed treshold, take appropriate connection ####
		if (TmpMongoDB.find_one({'Location': GeoQuery}))['Occurance'] > 5:
			print 'WARNING'
		else:
			print 'At least suspicious'

	else:

		#### Geo safe ####
		print 'Geolocation passed: {}'.format(GeoQuery)