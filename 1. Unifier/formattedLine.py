class FormattedLine(object):
	""" Unified object originating from different log formats """
	
	def __init__(self, index, ip, date, time, timezone, method, requestUrl, code, size, url, uagent):
		self.index = index
		self.ip = ip

		self.date = date
		self.time = time
		self.timezone = timezone


		self.method = method
		self.requestUrl = requestUrl
		self.code = code
		self.size = size
		self.url = url
		self.uagent = uagent