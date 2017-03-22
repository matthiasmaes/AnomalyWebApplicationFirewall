import IP2Location;
IP2LocObj = IP2Location.IP2Location();
IP2LocObj.open("IP2LOCATION-LITE-DB1.BIN");
rec = IP2LocObj.get_all("185.14.169.113");
print rec.country_long



for x in xrange(1,10):
	print x