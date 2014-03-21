import logging
import datetime
try:
    import threading
except ImportError:
    threading = None

from django.conf import settings

class ThreadCollector(object):
    def __init__(self):
        if threading is None:
            raise NotImplementedError(
                "threading module is not available, "
                "this panel cannot be used without it")
        self.collections = {}  # a dictionary that maps threads to collections

    def get_collection(self, thread=None):
        """
        Returns a list of collected items for the provided thread, of if none
        is provided, returns a list for the current thread.
        """
        if thread is None:
            thread = threading.currentThread()
        if thread not in self.collections:
            self.collections[thread] = []
        return self.collections[thread]

    def clear_collection(self, thread=None):
        if thread is None:
            thread = threading.currentThread()
        if thread in self.collections:
            del self.collections[thread]

    def collect(self, item, thread=None):
        self.get_collection(thread).append(item)

MESSAGE_IF_STRING_REPRESENTATION_INVALID = '[Could not get log message]'

class ThreadTrackingHandler(logging.Handler):
    def __init__(self, collector):
        logging.Handler.__init__(self)
        self.collector = collector

    def emit(self, record):
        try:
            message = self.format(record)
        except Exception:
            message = MESSAGE_IF_STRING_REPRESENTATION_INVALID

        record = {
            'message': message,
            'time': datetime.datetime.fromtimestamp(record.created),
            'level': record.levelname,
            'file': record.pathname,
            'line': record.lineno,
            'channel': record.name,
        }
        self.collector.collect(record)


# We don't use enable/disable_instrumentation because logging is global.
# We can't add thread-local logging handlers. Hopefully logging is cheap.

collector = ThreadCollector()
logging_handler = ThreadTrackingHandler(collector)
logging.root.setLevel(logging.NOTSET)
logging.root.addHandler(logging_handler)

class LoggingCollectorMiddleware(object):
    def process_request(self, request):
        collector.clear_collection()

    def show_logs(self, request):
        if request.META.get('REMOTE_ADDR', None) in settings.INTERNAL_IPS:
            return True

    def process_exception(self, request, exception):
        if self.show_logs(request):
            request.logs = collector.get_collection()
            request.exception = exception