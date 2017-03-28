import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler


class MyHandler(PatternMatchingEventHandler):
	patterns = ["*.xml", "*.lxml"]

	def process(self, event):
		print event.src_path, event.event_type  # print now only for degug

	def on_modified(self, event):
		self.process(event)

		def on_created(self, event):
			self.process(event)




if __name__ == '__main__':
	observer = Observer()
	observer.schedule(MyHandler(), path='C:/Users/bebxadvmmae/Desktop')
	observer.start()

	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()

		observer.join()