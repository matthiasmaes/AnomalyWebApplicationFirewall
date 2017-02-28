from pymongo import MongoClient
import IP2Location
from optparse import OptionParser


#### Init mongo DBs ####
ConfigMongoDB = MongoClient().Firewall.StaticConfig
StreamMongoDB = MongoClient().Firewall.TestStream
TmpMongoDB = MongoClient().Firewall.tmp
ProfileMongoDB = MongoClient().Profiles['8_15_35_Profile']



parser = OptionParser()
parser.add_option("-u", "--unfamiliar", action="store", dest="unfamiliarThreshold", default="5", help="Threshold for unfamiliar locations")
parser.add_option("-r", "--ratio", action="store", dest="ratioThreshold", default="0.15", help="Threshold for location ratio")
options, args = parser.parse_args()



def CheckGeoLocation(packet):
    """Check for anomalies in geolocation"""

	#### Test if var is definded ####
	try:
		packet
	except NameError:
		pass
	
	#### Geo locate ip address ####
	IP2LocObj = IP2Location.IP2Location();
	IP2LocObj.open('C:/Users/bebxadvmmae/Desktop/REMOTE/2. Profiler/sources/IP2GEODB.BIN');
	GeoQuery = IP2LocObj.get_all(packet['ip']).country_long;

	#### Check for geolocation ####
	if ConfigMongoDB.find({'Category': 'Location', 'Data': GeoQuery}).count() > 0:

		#### If location is in black list take appropriate action ####
		if (ConfigMongoDB.find_one({'Category': 'Location', 'Data': GeoQuery}))['Action'] == 'Alert' :
			print '[ALERT] Connection made from blacklisted country ({})'.format(GeoQuery)

	elif GeoQuery not in (ProfileMongoDB.find_one({ 'url' : packet['url'] }))['location']:

		#### Keep counter on unknown locations ####
		if TmpMongoDB.find({'Location': GeoQuery, 'url' : packet['url']}).count() == 0:
			TmpMongoDB.insert_one({'Location': GeoQuery, 'Occurance' : 0, 'Level' : 'Untrusted', 'url' : packet['url']})
		TmpMongoDB.update({'Location': GeoQuery}, {'$inc': { 'Occurance' : 1 }})

		#### If connections counter exceed treshold, take appropriate connection ####
		if (TmpMongoDB.find_one({'Location': GeoQuery}))['Occurance'] > int(options.unfamiliarThreshold):
			print '[ALERT] Unfamiliar location is making a lot of requests ({})'.format(GeoQuery)
		else:
			print '[WARNING] Unfamiliar location connected ({})'.format(GeoQuery)
	else:

		#### Keep counter on unknown locations ####
		if TmpMongoDB.find({'Location': GeoQuery, 'url' : packet['url']}).count() == 0:
			TmpMongoDB.insert_one({'Location': GeoQuery, 'Occurance' : 0, 'Level' : 'Trusted', 'url' : packet['url']})
		TmpMongoDB.update({'Location': GeoQuery, 'url' : packet['url']}, {'$inc': { 'Occurance' : 1 }})

	#### Determine ratio ####
	totalOccurance = 0

	#### Get total occurances from trusted location ####
	for x in TmpMongoDB.find({'Level' : 'Trusted'}):
		totalOccurance += x['Occurance']

	#### Calculate ratio for every location ####
	for x in TmpMongoDB.find({'Level' : 'Trusted'}):	

		ratio = float(x['Occurance']) / float(totalOccurance)

		#??# Does this need to be stored in the db?
		TmpMongoDB.update({'Location': x['Location'], 'url' : x['url']},{'$set' : {'Ratio': ratio}})

		ratioDiff =  ratio - (ProfileMongoDB.find_one({'url' : x['url']}))['location'][x['Location']]

		if ratioDiff > float(options.ratioThreshold) or ratioDiff < float(options.ratioThreshold) * -1:
			print '[Alert] Ratio treshold has been exceeded ({})'.format(x['Location'])


#### Main method ####
if __name__ == '__main__':
	for packet in StreamMongoDB.find():
		CheckGeoLocation(packet)