class Record(object):
	""" Record in profile """

	def __init__(self, expected_method, url):
		self.url = url
		self.expected_method = expected_method
		self.totalConnections = 0

		self.metric_geo = {}
		self.metric_agent = {}
		self.metric_time = {}
		self.metric_day = {}
		self.metric_ext = {}
		self.metric_param = {}
		self.metric_request = {}

	def __eq__(self, other):
		""" Test if records are equal """
		return self.url == other.url

	def getIP(self):
		""" Get IP-Address """
		return self.ip

	def getURL(self):
		""" Get URL """
		return self.url