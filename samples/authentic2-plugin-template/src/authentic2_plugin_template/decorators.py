import functools

from django.http import Http404

from . import app_settings

def plugin_enabled(view):
    '''If plugin is not enabled, return 404'''
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not app_settings.ENABLED:
            raise Http404
        return view(*args, **kwargs)
    return wrapper
