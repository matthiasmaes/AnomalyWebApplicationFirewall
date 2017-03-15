class FormattedLine(object):
	""" Unified object originating from different log formats """

	def __init__(self, index, ip, date, hour, minute, second, fulltime, method, requestUrl, code, size, url, uagent):
		self.index = index
		self.ip = ip

		self.date = date
		self.hour = hour
		self.minute = minute
		self.second = second
		self.fulltime = fulltime


		self.method = method
		self.requestUrl = requestUrl
		self.code = code
		self.size = size
		self.url = url
		self.uagent = uagent