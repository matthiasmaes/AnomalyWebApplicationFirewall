class Record_User(object):
	""" Record in profile """

	def __init__(self, ip, location):
		self.ip = ip
		self.location = location

		self.request_url = {}
		self.request_resource = {}


	def __eq__(self, other):
		""" Test if records are equal """
		return self.ip == other.ip