class FormattedLine:
	def __init__(self, ip, timestamp, method, requestUrl, code, size, url, uagent):
		self.ip = ip
		self.timestamp = timestamp
		self.method = method
		self.requestUrl = requestUrl
		self.code = code
		self.size = size
		self.url = url
		self.uagent = uagent