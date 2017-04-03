import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler


class MyHandler(PatternMatchingEventHandler):
	def on_modified(self, event):

		print 'Event' + event
		# with open('C:/wamp64/logs/access.log', 'r') as f:
		# 	### TODO: first and last line won't be read
		# 	seekOn = 0
		# 	for x in xrange(0, -500, -1):
		# 		try:
		# 			f.seek(x, 2)
		# 			if repr(f.readline()) == repr('\n'):
		# 				if x + 1 < -4:
		# 					break
		# 		except Exception as e:
		# 			pass

		# 	print repr(f.readline())




if __name__ == '__main__':
	observer = Observer()
	observer.schedule(MyHandler(), path='C:/wamp64/logs')
	observer.start()

	try:
		print 'Capturing...'
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()
	observer.join()