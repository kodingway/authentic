import logging
import hashlib

from django.core.cache import cache

from . import app_settings

def key(identifier):
    return 'user-login-failure-%s' % hashlib.md5(identifier).hexdigest()

def user_login_success(identifier):
    cache.delete(key(identifier))

def user_login_failure(identifier):
    cache.add(key(identifier), 0)
    count = cache.incr(key(identifier))
    if app_settings.A2_LOGIN_FAILURE_COUNT_BEFORE_WARNING and count >= app_settings.A2_LOGIN_FAILURE_COUNT_BEFORE_WARNING:
        logger = logging.getLogger('authentic2.user_login_failure')
        identifier = unicode(identifier)
        identifier = identifier.encode('utf-8')
        logger.warning('user %s failed to login more than %d times in a row', identifier, count)
