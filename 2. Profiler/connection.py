import IP2Location
import dns.resolver

class Connection(object):
	""" Object that represents a connection, one log entry """

	def __init__(self, ip, time, connectionDay, ping, typeConn, orgURL):
		try:
			IP2LocObj = IP2Location.IP2Location();
			IP2LocObj.open("sources\IP2GEODB.BIN");
			GeoQuery = IP2LocObj.get_all(ip).country_long;
		except Exception:
			if ping:
				try:
					GeoQuery = IP2LocObj.get_all(dns.resolver.query(ip, 'A')[0]).country_long;
				except Exception:
					GeoQuery = "Geolocation failed"
			else:
				GeoQuery = "Domain translation disabled"

		self.ip = ip
		self.location = GeoQuery
		self.time = time
		self.connectionDay = connectionDay
		self.typeConn = typeConn
		self.orgURL = orgURL

	def getLocation(self):
		""" Get location of connection """
		return self.location