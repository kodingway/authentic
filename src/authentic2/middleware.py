import urlparse
import logging
import datetime
import random
import struct
try:
    import threading
except ImportError:
    threading = None

from django.conf import settings
from django.contrib import messages
from django.utils.translation import ugettext as _
from django.shortcuts import render

from . import app_settings, utils, plugins

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

class CollectIPMiddleware(object):
    def process_request(self, request):
        ips = set(request.session.setdefault('ips', []))
        ip = request.META.get('REMOTE_ADDR', None)
        if ip and ip not in ips:
            ips.add(ip)
            request.session['ips'] = list(ips)
            request.session.modified = True

class OpenedSessionCookieMiddleware(object):
    def process_response(self, request, response):
        if not app_settings.A2_OPENED_SESSION_COOKIE_DOMAIN:
            return response
        name = app_settings.A2_OPENED_SESSION_COOKIE_NAME
        if app_settings.A2_OPENED_SESSION_COOKIE_NAME == 'parent':
            domain = request.get_host().split('.', 1)[1]
        else:
            domain = app_settings.A2_OPENED_SESSION_COOKIE_DOMAIN
        if hasattr(request, 'user') and request.user.is_authenticated():
            response.set_cookie(name, value='1', max_age=None, domain=domain)
        elif app_settings.A2_OPENED_SESSION_COOKIE_NAME in request.COOKIES:
            response.delete_cookie(name, domain=domain)
        return response

class RequestIdMiddleware(object):
    def process_request(self, request):
        if not hasattr(request, 'request_id'):
            request_id_header = getattr(settings, 'REQUEST_ID_HEADER', None)
            if request_id_header and request.META.get(request_id_header):
                request.request_id = request.META[request_id_header]
            else:
                # Use Mersennes Twister rng, no need for a cryptographic grade
                # rng in this case
                random_id = random.getrandbits(32)
                request.request_id = struct.pack('I', random_id).encode('hex')

class StoreRequestMiddleware(object):
    collection = {}

    def process_request(self, request):
        StoreRequestMiddleware.collection[threading.currentThread()] = request

    def process_response(self, request, response):
        StoreRequestMiddleware.collection.pop(threading.currentThread(), None)
        return response

    @classmethod
    def get_request(cls):
        return cls.collection.get(threading.currentThread())

class ViewRestrictionMiddleware(object):
    RESTRICTION_SESSION_KEY = 'view-restriction'

    def check_view_restrictions(self, request):
        '''Check if a restriction on accessible views must be applied'''
        from django.db.models import Model
        from .models import PasswordReset

        user = request.user
        if user.is_authenticated() \
                and isinstance(user, Model) \
                and PasswordReset.objects.filter(user=request.user).exists():
            return 'password_change'
        for plugin in plugins.get_plugins():
            if hasattr(plugin, 'check_view_restrictions'):
                view = plugin.check_view_restrictions(request)
                if view:
                    return view

    def process_view(self, request, view_func, view_args, view_kwargs):
        '''If current view is not the one we should be, redirect'''
        view = self.check_view_restrictions(request)
        if not view or request.resolver_match.url_name in (view, 'auth_logout'):
            return
        if view == 'password_change':
            messages.warning(request, _('You must change your password to continue'))
        return utils.redirect_and_come_back(request, view)

class XForwardedForMiddleware(object):
    '''Copy the first address from X-Forwarded-For header to the REMOTE_ADDR meta.

       This middleware should only be used if you are sure the header cannot be
       forged (behind a reverse proxy for example).'''
    def process_request(self, request):
        if 'HTTP_X_FORWARDED_FOR' in request.META:
            request.META['REMOTE_ADDR'] = request.META['HTTP_X_FORWARDED_FOR'].split(",")[0].strip()
            return None

class DisplayMessageBeforeRedirectMiddleware(object):
    def process_response(self, request, response):
        if response.status_code not in (302, 307):
            return response
        storage = messages.get_messages(request)
        if not storage:
            return response
        # Check if all messages are info
        only_info = True
        for message in storage:
            if message.level != messages.INFO:
                only_info = False
        storage.used = False
        url = response['Location']
        if not url:
            return response
        parsed_url = urlparse.urlparse(url)
        if not parsed_url.scheme and not parsed_url.netloc:
            return response
        parsed_request_url = urlparse.urlparse(request.build_absolute_uri())
        if (parsed_request_url.scheme == parsed_url.scheme or not parsed_url.scheme) and \
                (parsed_request_url.netloc == parsed_url.netloc):
            return response
        return render(request, 'authentic2/display_message_and_continue.html',
                      {'url': url, 'only_info': only_info})
