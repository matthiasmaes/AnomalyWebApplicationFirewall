import IP2Location
import dns.resolver


class Connection:
	def __init__(self, ip, time, ping, typeConn, orgURL):
		try:
			IP2LocObj = IP2Location.IP2Location();
			IP2LocObj.open("sources\IP2GEODB.BIN");
			GeoQuery = IP2LocObj.get_all(ip).country_long;
		except Exception as e:
			if ping:
				try:
					GeoQuery = IP2LocObj.get_all(dns.resolver.query(ip, 'A')[0]).country_long;
				except Exception as e:
					GeoQuery = "Geolocation failed"
			else:
				GeoQuery = "Domain translation disabled"

		self.ip = ip
		self.location = GeoQuery
		self.time = time
		self.typeConn = typeConn
		self.orgURL = orgURL