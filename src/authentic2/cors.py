from .decorators import SessionCache
import urlparse

from django.conf import settings

from . import plugins, app_settings


def make_origin(url):
    '''Build origin of an URL'''
    parsed = urlparse.urlparse(url)
    if ':' in parsed.netloc:
        host, port = parsed.netloc.split(':', 1)
        if parsed.scheme == 'http' and port == 80:
            port = None
        if parsed.scheme == 'https' and port == 443:
            port = None
    else:
        host, port = parsed.netloc, None
    result = '%s://%s' % (parsed.scheme, host)
    if port:
        result += ':%s' % port
    return result


@SessionCache(timeout=60, args=(1,))
def check_origin(request, origin):
    '''Decide if an origin is authorized to do a CORS request'''
    if settings.DEBUG:
        return True
    request_origin = make_origin(request.build_absolute_uri())
    if origin == 'null':
        return False
    if not origin:
        return False
    if origin == request_origin:
        return True
    # A2_CORS_WHITELIST must contain properly formatted origins (i.e. only
    # scheme and netloc, no path and port must be normalized)
    for whitelist_origin in app_settings.A2_CORS_WHITELIST:
        if whitelist_origin == origin:
            return True
    for plugin in plugins.get_plugins():
        if hasattr(plugin, 'check_origin'):
            if plugin.check_origin(request, origin):
                return True
    return False


