class Record_User(object):
	""" Record in profile """

	def __init__(self, ip, location):
		self.general_ip = ip
		self.general_location = location
		self.general_totalConnections = 0
		self.general_timeline = {}

		#### Init all metrics ####
		self.metric_agent = {}
		self.metric_time = {}
		self.metric_day = {}
		self.metric_param = {}
		self.metric_url = {}
		self.metric_request = {}
		self.metric_timespent = {}
		self.metric_status = {}
		self.metric_method = {}
	def __eq__(self, other):
		""" Test if records are equal """
		return self.ip == other.ip