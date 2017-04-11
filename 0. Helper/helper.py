import IP2Location
import dns.resolver
import string
import datetime
import math

from collections import OrderedDict
from optparse import OptionParser
from formattedLine import FormattedLine

class TYPE(object):
	USER, APP = range(2)

class SCRIPT(object):
	PROFILER, FIREWALL = range(2)

class SEVERITY(object):
	CRITICAL, HIGH, LOW = range(3)


class Helper(object):

	def __init__(self):
		pass

	def __get__(self):
		return self.val

	def __set__(self, obj, val):
		self.val = val

	def setupParser(self):
		parser = OptionParser()
		parser.add_option("-p", "--ping", action="store_true", dest="ping", default=True, help="Try to resolve originating domains to ip for geolocation")
		parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="Show debug messages")
		parser.add_option("-t", "--threads", action="store", dest="threads", default="12", help="Amout of threats that can be used")
		parser.add_option("-x", "--lines", action="store", dest="linesPerThread", default="100", help="Max lines per thread")
		parser.add_option("-m", "--mongo", action="store", dest="inputMongo", default="TEST", help="Input via mongo")
		parser.add_option("-s", "--start", action="store", dest="startIndex", default="0", help="Start index for profiling")
		parser.add_option("-e", "--end", action="store", dest="endindex", default="0", help="End index for profiling")
		return parser.parse_args()

	def GeoLocate(self, ip, ping):
		""" Method for translating ip-address to geolocation (country) """

		if ip == '::1':
			return 'Belgium'

		try:
			IP2LocObj = IP2Location.IP2Location();
			IP2LocObj.open("sources\IP2GEODB.BIN");
			return IP2LocObj.get_all(ip).country_long;
		except Exception as e:
			print 'geo'
			print e
			if ping:
				try:
					return IP2LocObj.get_all(dns.resolver.query(ip, 'A')[0]).country_long;
				except Exception:
					return "Geolocation failed"
			else:
				return "Domain translation disabled"

	def monthAbbrToInt(self, abbr):
		return{
		        'Jan' : 1, 'Feb' : 2, 'Mar' : 3, 'Apr' : 4, 'May' : 5, 'Jun' : 6, 'Jul' : 7, 'Aug' : 8,
		        'Sep' : 9, 'Oct' : 10,'Nov' : 11,'Dec' : 12
		}[abbr]


	def processLine(self, inputLine, index):
		index += 1
		cleandedLine = filter(None, [x.strip() for x in inputLine.replace('""','"-"').split('"')])
		ip = cleandedLine[0].split(' ')[0]
		fulltime = cleandedLine[0].split(' ')[3].replace('[', '') + ' ' +  cleandedLine[0].split(' ')[4].replace(']', '')
		method = cleandedLine[1].split(' ')[0]
		requestUrl = '-' if cleandedLine[1] == '-' else cleandedLine[1].split(' ')[1]
		code = cleandedLine[2].split(' ')[0]
		size = cleandedLine[2].split(' ')[1]
		url = cleandedLine[3]
		uagent = cleandedLine[4]
		return FormattedLine(index, ip, fulltime, method, requestUrl, code, size, url, uagent).__dict__


	def calculateRatio(self, value, metric):
		""" Method for calculating the ratio for a given metric """

		currRecord = self.OutputMongoDB.find_one({'_id': value })
		for metricEntry in currRecord[metric]:
			if metricEntry is not '' or metricEntry is not None:
				self.OutputMongoDB.update({'_id': value}, {'$set': {metric + '.' + metricEntry + '.ratio': float(currRecord[metric][metricEntry]['counter']) / float(currRecord['general_totalConnections'])}})


	def calculateRatioParam(self, key, queryString):
		""" Method for calculating the ratio for a given metric """
		currRecord = self.OutputMongoDB.find_one({'_id': key })

		if len(queryString) > 0:
			for param in queryString:
				if len(param.split('=')) == 2:
					pKey = param.split('=')[0]
					for param in currRecord['metric_param'][pKey]:
						try:
							#### Update ratio on all affected records and metrics (if counter changes on one metric, ratio on all has to be updated) ####
							self.OutputMongoDB.update({'_id': key}, {'$set': { 'metric_param' + '.' + pKey + '.' + param + '.ratio': float(currRecord['metric_param'][pKey][param]['counter']) / float(currRecord['metric_param'][pKey]['counter'])}})
						except TypeError:
							#### Not every metric has a counter/ratio field, this will be catched by the TypeError exception ####
							pass



	def getQueryString(self, inputLine):
		return inputLine.split('?')[1].split('&') if '?' in str(inputLine) else ''


	def getUrlWithoutQuery(self, inputLine):
		return inputLine.split('?')[0] if '?' in str(inputLine) else inputLine


	def getFileType(self, inputLine):
		try:
			filetype = inputLine.split('.')[1].split('?')[0]
		except Exception:
			try:
				filetype = inputLine.split('.')[1]
			except Exception:
				filetype = 'url'
		return filetype


	def makeTimeline(self, identifier, otherIdentifier):
		timelineDict = self.OutputMongoDB.find_one({'_id' : identifier})['general_timeline']
		timelineList = map(list, OrderedDict(sorted(timelineDict.items(), key=lambda t: datetime.datetime.strptime(t[0], '%d/%b/%Y %H:%M:%S'))).items())

		for event in timelineList:
			#### Calculate avg time spent for each base url ####
			if timelineList.index(event) == len(timelineList) - 1:
				break

			time1 = datetime.datetime.strptime(event[0], '%d/%b/%Y %H:%M:%S')
			time2 = datetime.datetime.strptime(timelineList[timelineList.index(event)+1][0], '%d/%b/%Y %H:%M:%S')

			delta = time2 - time1


			if delta.total_seconds() > 5 and delta.total_seconds() < 3600:
				self.calculateNewAverageDeviance(identifier, otherIdentifier, 'metric_timespent', delta.total_seconds())


	def calulateAvgSize(self, identifier, otherIdentifier, size):
		self.calculateNewAverageDeviance(identifier, otherIdentifier, 'metric_size', int(size))


	def calculateNewAverageDeviance(self, identifier, otherIdentifier, metric, newVal):

		counter = self.OutputMongoDB.find_one({ '_id' : identifier })['metric_conn'][otherIdentifier]['counter']

		# MIN #
		try:
			orgMin =self.OutputMongoDB.find_one({ '_id' : identifier })[metric][otherIdentifier]['min']
			newMin = newVal if newVal < orgMin else orgMin
		except KeyError:
			newMin = newVal
		finally:
			self.OutputMongoDB.update_one({ '_id' : identifier }, { '$set' : {metric + '.' + otherIdentifier + '.min': int(newMin)}})

		# MAX #
		try:
			orgMax =self.OutputMongoDB.find_one({ '_id' : identifier })[metric][otherIdentifier]['max']
			newMax = newVal if newVal > orgMax else orgMax
		except KeyError:
			newMax = newVal
		finally:
			self.OutputMongoDB.update_one({ '_id' : identifier }, { '$set' : {metric + '.' + otherIdentifier + '.max': int(newMax)}})


		# AVERAGE #
		try:
			orgAvg = self.OutputMongoDB.find_one({ '_id' : identifier })[metric][otherIdentifier]['average']
			newAvg = (orgAvg * (counter - 1) + newVal) / counter

		except KeyError:
			newAvg = newVal

		except Exception as e:
			print e

		finally:
			self.OutputMongoDB.update_one({ '_id' : identifier }, { '$set' : {metric + '.' + otherIdentifier + '.average': int(newAvg)}})


		# DEVIANCE #
		try:
			orgDeviation = math.pow((self.OutputMongoDB.find_one({ '_id' : identifier })[metric][otherIdentifier]['deviation']),2)
			# STEEKPROEF
			# newDeviation = (((counter - 2) * orgDeviation) + (newVal - newAvg) * (newVal - orgAvg)) / (counter - 1)

			# POPULATIE
			newDeviation = (((counter-1) * orgDeviation) + (newVal - newAvg) * (newVal - orgAvg)) / (counter)

		except KeyError:
			newDeviation = 0
		finally:
			self.OutputMongoDB.update_one({ '_id' : identifier }, { '$set' : {metric + '.' + otherIdentifier + '.deviation': math.sqrt(int(newDeviation))}})



	def processLineCombined(self, typeProfile, script, inputLine, options):

		if typeProfile == TYPE.USER:
			key = inputLine['ip']
			otherKey = self.getUrlWithoutQuery(inputLine['url']).replace('.','_')
		elif typeProfile == TYPE.APP:
			key = self.getUrlWithoutQuery(inputLine['url'])
			otherKey = inputLine['ip'].replace('.','_')

		if inputLine is None:
			print '--- NONE ---'
			return

		try:
			timestamp = datetime.datetime.strptime(inputLine['fulltime'].split(' ')[0], '%d/%b/%Y:%H:%M:%S')
		except Exception as e:
			split = inputLine['fulltime'].replace(' ',':').replace('/',':').split(':')

			timestamp = datetime.datetime(int(split[2]), self.monthAbbrToInt(split[1]) , int(split[0]), int(split[3]), int(split[4]), int(split[5]), 0)

		urlWithoutQuery = self.getUrlWithoutQuery(inputLine['url']).replace('.', '_')
		queryString = [element.replace('.', '_') for element in self.getQueryString(inputLine['url'])]

		#### Insert record if it doesn't exists ####
		if self.OutputMongoDB.find({'_id': key}).count() == 0:
			try:
				self.OutputMongoDB.update_one({'_id': key}, {'$set': {'metric_param': {}}} , upsert=True)
			except Exception as e:
				if 'E11000' in e.message:
					pass
				else:
					raise e


		#### Setup bulk stream ####
		bulk = self.OutputMongoDB.initialize_unordered_bulk_op()
		bulk.find({'_id': key}).update_one({'$inc': {'general_totalConnections': 1 }})
		bulk.find({'_id': key}).update_one({'$set': {'general_timeline.' + timestamp.strftime('%d/%b/%Y %H:%M:%S'): otherKey}})
		if typeProfile == TYPE.USER:
			bulk.find({'_id': key}).update_one({'$set': {'general_location': self.GeoLocate(inputLine['ip'], options.ping) }})
		elif typeProfile == TYPE.APP:
			bulk.find({'_id': key}).update_one({'$inc': {'metric_location.' + self.GeoLocate(inputLine['ip'], options.ping) + '.counter': 1 }})
		bulk.find({'_id': key}).update_one({'$inc': {'metric_day.' + timestamp.strftime("%A") + '.counter': 1 }})
		bulk.find({'_id': key}).update_one({'$inc': {'metric_time.' + timestamp.strftime("%H") + '.counter': 1 }})
		bulk.find({'_id': key}).update_one({'$inc': {'metric_agent.' + inputLine['uagent'].replace('.', '_') + '.counter': 1 }})
		bulk.find({'_id': key}).update_one({'$set': {'metric_agent.' + inputLine['uagent'].replace('.', '_') + '.uagentType': 'Human' if self.BotMongoDB.find({'agent': inputLine['uagent']}).count() == 0 else 'Bot' }})
		bulk.find({'_id': key}).update_one({'$inc': {'metric_request.' + inputLine['requestUrl'].replace('.', '_') + '.counter': 1 }})
		bulk.find({'_id': key}).update_one({'$inc': {'metric_ext.' + self.getFileType(inputLine['requestUrl']) +'.counter': 1 }})
		bulk.find({'_id': key}).update_one({'$inc': {'metric_status.' + inputLine['code'] +'.counter': 1 }})
		bulk.find({'_id': key}).update_one({'$inc': {'metric_method.' + inputLine['method'] +'.counter': 1 }})
		bulk.find({'_id': key}).update_one({'$inc': {'metric_conn.' + otherKey + '.counter': 1 }})

		#### Categorize conn admin/user/normal ####
		if len([s for s in self.AdminMongoList if s in urlWithoutQuery]) != 0:
			bulk.find({'_id': key}).update_one({'$inc': { 'metric_login.admin.counter': 1 }})
			loginResult = 'admin'
		elif len([s for s in self.UserMongoList if s in urlWithoutQuery]) != 0:
			bulk.find({'_id': key}).update_one({'$inc': { 'metric_login.user.counter': 1 }})
			loginResult = 'user'
		else:
			bulk.find({'_id': key}).update_one({'$inc': { 'metric_login.normal.counter': 1 }})
			loginResult = 'normal'

		#### Add querystring param ####
		if len(queryString) > 0:
			for param in queryString:
				if len(param.split('=')) == 2:
					pKey = param.split('=')[0]
					pValue = '-' if not param.split('=')[1] else param.split('=')[1]

					#### Determine type of param ####
					try:
						int(pValue)
						paramType = 'int'
					except ValueError:
						paramType = 'bool' if pValue == 'true' or pValue == 'false' else 'string'
					except Exception:
						print param

					#### Detecting special chars in param ####
					chars = 'special' if any(char in string.punctuation for char in pValue) else 'normal'

					#### Add to bulk updates ####
					bulk.find({'_id': key}).update_one({'$set': { 'metric_param.' + pKey + '.characters': chars}})
					bulk.find({'_id': key}).update_one({'$set': { 'metric_param.' + pKey + '.length': len(pValue)}})
					bulk.find({'_id': key}).update_one({'$set': { 'metric_param.' + pKey + '.type': paramType}})
					bulk.find({'_id': key}).update_one({'$inc': { 'metric_param.' + pKey + '.' + pValue + '.counter': 1}})
					bulk.find({'_id': key}).update_one({'$inc': { 'metric_param.' + pKey + '.counter': 1}})


		#### Execute bulk statement ####
		try:
			bulk.execute()
		except Exception as e:
			print e.details


		#### See self.py for details on functions ####
		self.makeTimeline(key, otherKey)
		self.calulateAvgSize(key, otherKey, inputLine['size'])


		self.calculateRatio(key, 'metric_agent')
		self.calculateRatio(key, 'metric_time')
		self.calculateRatio(key, 'metric_day')
		self.calculateRatio(key, 'metric_request')
		self.calculateRatio(key, 'metric_status')
		self.calculateRatio(key, 'metric_method')
		self.calculateRatio(key, 'metric_ext')
		self.calculateRatio(key, 'metric_login')
		self.calculateRatio(key, 'metric_conn')
		self.calculateRatioParam(key, queryString)

		if typeProfile == TYPE.APP:
			self.calculateRatio(key, 'metric_location')



		if script == SCRIPT.FIREWALL:
			return {
				'_id': key,
				'metric_param': queryString,

				'metric_method': inputLine['method'],
				'metric_day': timestamp.strftime("%A"),
				'metric_status': inputLine['code'],
				'metric_agent': inputLine['uagent'].replace('.', '_'),
				'metric_login': loginResult,
				'metric_timespent': None,
				'metric_location': self.GeoLocate(inputLine['ip'], True),
				'metric_time': timestamp.strftime("%H"),
				'metric_ext': self.getFileType(inputLine['requestUrl']),
				'metric_request': inputLine['requestUrl'].replace('.', '_'),
				'metric_conn': otherKey
			}
