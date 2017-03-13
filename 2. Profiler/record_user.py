class Record_User(object):
	""" Record in profile """

	def __init__(self, ip, location):
		self.ip = ip
		self.location = location
		self.totalConnections = 0


		self.metric_agent = {}
		self.metric_time = {}
		self.metric_day = {}

		self.metric_url = {}
		self.metric_request = {}




	def __eq__(self, other):
		""" Test if records are equal """
		return self.ip == other.ip