class Record(object):
	""" Record in profile """

	def __init__(self, expected_method, url, expected_code, expected_size):
		self.url = url
		self.expected_method = expected_method
		self.expected_code = expected_code
		self.expected_size = expected_size
		self.connection = []
		self.location = {}
		self.activity = {'Monday': 0, 'Tuesday': 0, 'Wednesday': 0, 'Thursday': 0, 'Friday': 0, 'Saturday': 0, 'Sunday': 0}


	def __eq__(self, other):
		""" Test if records are equal """
		return self.url == other.url

	def getIP(self):
		""" Get IP-Address """
		return self.ip

	def getURL(self):
		""" Get URL """
		return self.url