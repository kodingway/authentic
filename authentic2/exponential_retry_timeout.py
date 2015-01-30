import time
import logging

from django.core.cache import cache

def username_key(request):
    return request.user.get_username()

def remote_addr_key(request):
    return request.META['REMOTE_ADDR']

class ExponentialRetryTimeout(object):
    FACTOR = 1.8
    DURATION = 0.8
    MAX_DURATION = 3600 # max 1 hour
    KEY_PREFIX = 'exponential-backoff-'
    CACHE_DURATION = 86400

    def __init__(self, factor=FACTOR, duration=DURATION,
            max_duration=MAX_DURATION, key_prefix=KEY_PREFIX,
            cache_duration=CACHE_DURATION,
            key_function=remote_addr_key):
        self.factor = factor
        self.duration = duration
        self.max_duration = max_duration
        self.key_prefix = key_prefix
        self.key_function = key_function
        self.cache_duration = cache_duration
        self.logger = logging.getLogger(__name__)

    def key(self, request):
        return self.key_prefix + self.key_function(request)

    def seconds_to_wait(self, request):
        '''Return the duration in seconds until the next time when an action can be
           done.
        '''
        now = time.time()
        what = cache.get(self.key(request))
        if what and what[1] > now:
            return what[1] - now

    def success(self, request):
        '''Signal an action success, delete exponential backoff cache.
        '''
        cache.delete(self.key(request))

    def failure(self, request):
        '''Signal an action failure, augment the exponential backoff one level.
        '''
        what = cache.get(self.key(request))
        if not what:
            now = time.time()
            what = 0, now+self.duration
            cache.set(self.key(request), what, self.cache_duration)
        else:
            level, next_time = what
            level += 1
            duration = min(self.duration*self.factor**level, self.max_duration)
            next_time += duration
            what = level, next_time
            cache.set(self.key(request), (level, next_time), self.cache_duration)
