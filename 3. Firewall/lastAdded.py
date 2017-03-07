class LastAdded(object):
	""" Object that represents last added log entry """

	def __init__(self):
		self.location = ''
		self.time = ''
		self.agent = ''
		self.ext = ''
		self.request = ''

		self.param = list()

	def addParam(self, param):
		self.param.append(param)

	def __get__(self, obj, objtype):
		return self.val

	def __set__(self, obj, val):
		self.val = val