import time
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler


def printEvent(Event):
    print Event

if __name__ == "__main__":
    path = 'C:/wamp64/logs' 
    observer = Observer()
    # observer.schedule(printEvent(), path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()