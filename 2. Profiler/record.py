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
		self.time = {'0' : 0, '1' : 0, '2' : 0, '3' : 0, '4' : 0, '5' : 0, '6' : 0, '7' : 0, '8' : 0, '9' : 0, '10' : 0, '11' : 0, '12' : 0, '13' : 0, '14' : 0, '15' : 0, '16' : 0, '17' : 0, '18' : 0, '19' : 0, '20' : 0, '21' : 0, '22' : 0, '23' : 0 }


	def __eq__(self, other):
		""" Test if records are equal """
		return self.url == other.url

	def getIP(self):
		""" Get IP-Address """
		return self.ip

	def getURL(self):
		""" Get URL """
		return self.url