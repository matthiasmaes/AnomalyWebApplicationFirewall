from pymongo import MongoClient
import IP2Location


ConfigMongoDB = MongoClient().Firewall.StaticConfig
StreamMongoDB = MongoClient().Firewall.TestStream

def alert():
	print '[ALERT] Connection made from blacklisted country'


actions = {'Alert' : alert(),}


for packet in StreamMongoDB.find():
	IP2LocObj = IP2Location.IP2Location();
	IP2LocObj.open('C:/Users/bebxadvmmae/Desktop/REMOTE/2. Profiler/sources/IP2GEODB.BIN');
	GeoQuery = IP2LocObj.get_all(packet['ip']).country_long;

	#### Check for geolocation ####
	if ConfigMongoDB.find({'Category': 'Location', 'Data': GeoQuery}).count() > 0:
		actions[(ConfigMongoDB.find_one({'Category': 'Location', 'Data': GeoQuery}))['Action']]
	else:
		print 'Geolocation passed: {}'.format(GeoQuery)