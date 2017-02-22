class FormattedLine:
	def __init__(self, ip, timestamp, request, code, size, url, uagent):
		self.ip = ip
		self.timestamp = timestamp
		self.request = request
		self.code = code
		self.size = size
		self.url = url
		self.uagent = uagent