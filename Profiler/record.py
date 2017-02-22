
import connection
import socket
class Record:

	def __init__(self, expected_method, url, expected_code, expected_size):
		self.url = url
		self.expected_method = expected_method
		self.expected_code = expected_code
		self.expected_size = expected_size
		self.connection = []

	def __eq__(self, other):
		return self.url == other.url

	def getIP(self):
		return self.ip

	def getURL(self):
		return self.url