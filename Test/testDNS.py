import dns.resolver


print dns.resolver.query('www.google.be', 'A')[0]


class Tester():
	pass