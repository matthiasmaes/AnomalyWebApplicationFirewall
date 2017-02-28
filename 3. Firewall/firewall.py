from pymongo import MongoClient
import IP2Location


ConfigMongoDB = MongoClient().Firewall.StaticConfig
StreamMongoDB = MongoClient().Firewall.TestStream
TmpMongoDB = MongoClient().Firewall.tmp
ProfileMongoDB = MongoClient().Profiles['8_15_35_Profile']



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
		if TmpMongoDB.find({'Location': GeoQuery, 'url' : packet['url']}).count() == 0:
			TmpMongoDB.insert_one({'Location': GeoQuery, 'Occurance' : 0, 'Level' : 'Untrusted', 'url' : packet['url']})
		TmpMongoDB.update({'Location': GeoQuery}, {'$inc': { 'Occurance' : 1 }})


		#### If connections counter exceed treshold, take appropriate connection ####
		if (TmpMongoDB.find_one({'Location': GeoQuery}))['Occurance'] > 5:
			print 'WARNING'
		else:
			print 'At least suspicious'


	else:

		#### Keep counter on unknown locations ####
		if TmpMongoDB.find({'Location': GeoQuery, 'url' : packet['url']}).count() == 0:
			TmpMongoDB.insert_one({'Location': GeoQuery, 'Occurance' : 0, 'Level' : 'Trusted', 'url' : packet['url']})
		TmpMongoDB.update({'Location': GeoQuery, 'url' : packet['url']}, {'$inc': { 'Occurance' : 1 }})


		#### Geo safe ####
		print 'Geolocation passed: {}'.format(GeoQuery)







	#### Determine ratio ####
	totalOccurance = 0

	for x in TmpMongoDB.find({'Level' : 'Trusted'}):
		totalOccurance += x['Occurance']


	for x in TmpMongoDB.find({'Level' : 'Trusted'}):	

		ratio = float(x['Occurance']) / float(totalOccurance)

		#??# Does this need to be stored in the db?
		TmpMongoDB.update({'Location': x['Location'], 'url' : x['url']},{'$set' : {'Ratio': ratio}})


		ratioDiff =  ratio - (ProfileMongoDB.find_one({'url' : x['url']}))['location'][x['Location']]

		if ratioDiff > 0.15 or ratioDiff < -0.15:
			print '[Alert] Difference in ratio: {}'.format(ratioDiff)
		else:
			print '[OK] Defference in ratio is ok {}'.format(ratioDiff)