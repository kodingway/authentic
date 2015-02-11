from django.core.exceptions import ImproperlyConfigured

from django.core.cache import InvalidCacheBackendError, cache, get_cache
from django.core.cache.backends.locmem import LocMemCache
from django.core.cache.backends.dummy import DummyCache


def get_shared_cache(name=None):
    '''Try to return a cache backend shared between requests. Fail by raising
       ImproperlyConfigured.
    '''
    candidate = cache
    try:
        candidate = get_cache('persistent')
    except InvalidCacheBackendError:
        pass
    if name is not None:
        try:
            candidate = get_cache(name)
        except InvalidCacheBackendError:
            pass
    if type(cache) in (DummyCache, LocMemCache):
        raise ImproperlyConfigured('no shared cache backend is configured for %r' % name)
    return cache

