class FormattedLine(object):
	""" Unified object originating from different log formats """
	def __init__(self, index, ip, timestamp, method, requestUrl, code, size, url, uagent):
		self.index = index
		self.ip = ip
		self.timestamp = timestamp
		self.method = method
		self.requestUrl = requestUrl
		self.code = code
		self.size = size
		self.url = url
		self.uagent = uagent