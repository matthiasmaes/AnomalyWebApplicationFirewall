from pymongo import MongoClient
import IP2Location
import calendar
import datetime

from optparse import OptionParser


#### Init mongo DBs ####
ConfigMongoDB = MongoClient().Firewall.StaticConfig
StreamMongoDB = MongoClient().Firewall.TestStream
TmpMongoDB = MongoClient().Firewall.tmp
ProfileMongoDB = MongoClient().Profiles['testCase']


weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
activity = {'Monday': 0, 'Tuesday': 0, 'Wednesday': 0, 'Thursday': 0, 'Friday': 0, 'Saturday': 0, 'Sunday': 0}
time = {'0' : 0, '1' : 0, '2' : 0, '3' : 0, '4' : 0, '5' : 0, '6' : 0, '7' : 0, '8' : 0, '9' : 0, '10' : 0, '11' : 0, '12' : 0, '13' : 0, '14' : 0, '15' : 0, '16' : 0, '17' : 0, '18' : 0, '19' : 0, '20' : 0, '21' : 0, '22' : 0, '23' : 0 }

parser = OptionParser()
parser.add_option("-u", "--unfamiliar", action="store", dest="unfamiliarThreshold", default="5", help="Threshold for unfamiliar locations")
parser.add_option("-r", "--ratio", action="store", dest="ratioThreshold", default="0.15", help="Threshold for location ratio")
parser.add_option("-a", "--activity", action="store", dest="activityThreshold", default="10", help="Threshold for activity/day")

options, args = parser.parse_args()



def GeoQueryLocal(ip):
	#### Geo locate ip address ####
	IP2LocObj = IP2Location.IP2Location();
	IP2LocObj.open('C:/Users/bebxadvmmae/Desktop/REMOTE/2. Profiler/sources/IP2GEODB.BIN');
	return IP2LocObj.get_all(ip).country_long;

def InsertDocument(location, url, level):
	if TmpMongoDB.find({'Location': location, 'url' : url}).count() == 0:
		TmpMongoDB.insert_one({'Location': location, 'Occurance' : 0, 'Level' : level, 'url' : url, 'activity': activity, 'time': time})
	



def CheckGeoLocation(packet):

	#### Test if var is definded ####
	try:
		packet
	except NameError:
		packet = 'Null'

	GeoQuery = GeoQueryLocal(packet['ip'])

	#### Check for geolocation ####
	if ConfigMongoDB.find({'Category': 'Location', 'Data': GeoQuery}).count() > 0:

		InsertDocument(GeoQuery, packet['url'], 'Blacklisted')
		TmpMongoDB.update({'Location': GeoQuery}, {'$inc': { 'Occurance' : 1 }})

		print '[ALERT] Connection made from blacklisted country ({})'.format(GeoQuery)

	elif GeoQuery not in (ProfileMongoDB.find_one({ 'url' : packet['url'] }))['location']:

		#### Keep counter on unknown locations ####
		InsertDocument(GeoQuery, packet['url'], 'Untrusted')
		TmpMongoDB.update({'Location': GeoQuery}, {'$inc': { 'Occurance' : 1 }})

		#### If connections counter exceed threshold, take appropriate connection ####
		if (TmpMongoDB.find_one({'Location': GeoQuery}))['Occurance'] > int(options.unfamiliarThreshold):
			print '[ALERT] Unfamiliar location is making a lot of requests ({})'.format(GeoQuery)
		else:
			print '[WARNING] Unfamiliar location connected ({})'.format(GeoQuery)
	else:

		#### GEO SAFE ####
		InsertDocument(GeoQuery, packet['url'], 'Trusted')
		TmpMongoDB.update({'Location': GeoQuery, 'url' : packet['url']}, {'$inc': { 'Occurance' : 1 }})






	#### Determine ratio ####
	totalOccurance = 0

	#### Get total occurances from trusted location ####
	for x in TmpMongoDB.find({'Level' : 'Trusted', 'url' : packet['url'] }):
		totalOccurance += x['Occurance']

	#### Calculate ratio for every location ####
	for x in TmpMongoDB.find({'Level' : 'Trusted', 'url' : packet['url'] }):	

		ratio = float(x['Occurance']) / float(totalOccurance)

		#??# Does this need to be stored in the db?
		TmpMongoDB.update({'Location': x['Location'], 'url' : x['url']},{'$set' : {'Ratio': ratio}})


		ratioDiff = ProfileMongoDB.find_one({'url' : x['url']})['location'][x['Location']] - ratio

		if ratioDiff > float(options.ratioThreshold):
			print '[Alert] Ratio threshold has been exceeded ({})'.format(x['Location'])





def CheckActivity(packet):
	GeoQuery = GeoQueryLocal(packet['ip'])

	splittedTime = packet['date'].split('/')
	connectionDay = weekdays[(datetime.datetime(int(splittedTime[2]), int(list(calendar.month_abbr).index(splittedTime[1])), int(splittedTime[0]))).weekday()]		

	TmpMongoDB.update({ 'Location': GeoQuery, 'url' : packet['url'] }, {'$inc': { 'activity.' + connectionDay: 1 }})

	for activityDay in activity:

		#### Get all connections frome same url ####
		productionConnections = 0
		for x in TmpMongoDB.find({ 'url' : packet['url'] }):
			productionConnections += x['activity'][activityDay]

		profileConnections = ProfileMongoDB.find_one({'url' : packet['url']})['activity'][activityDay]


		#### Test for threshold ####
		if productionConnections - profileConnections > int(options.activityThreshold):
			print '[Alert] Activity threshold has been exceeded ({})'.format(packet['url'])



def CheckTime(packet):
	GeoQuery = GeoQueryLocal(packet['ip'])

	TmpMongoDB.update({ 'Location': GeoQuery, 'url' : packet['url'] }, {'$inc': { 'time.' + packet['time']: 1 }})

	for timeStamp in time:

		#### Get all connections frome same url ####
		productionTimes = 0
		for x in TmpMongoDB.find({ 'url' : packet['url'] }):
			productionTimes += x['time'][timeStamp]

		profileTimes = ProfileMongoDB.find_one({'url' : packet['url']})['time'][timeStamp]

		#### Test for threshold ####
		if productionTimes - profileTimes > int(options.activityThreshold):
			print '[Alert] Time threshold has been exceeded ({})'.format(packet['url'])






#### Main method ####
if __name__ == '__main__':
	for packet in StreamMongoDB.find():
		CheckGeoLocation(packet)
		CheckActivity(packet)
		CheckTime(packet)