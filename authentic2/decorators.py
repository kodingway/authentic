from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, Http404
from functools import wraps

from . import utils, app_settings

TRANSIENT_USER_TYPES = []

def is_transient_user(user):
    return isinstance(user, tuple(TRANSIENT_USER_TYPES))

def prevent_access_to_transient_users(view_func):
    def _wrapped_view(request, *args, **kwargs):
        '''Test if the user is transient'''
        for user_type in TRANSIENT_USER_TYPES:
            if is_transient_user(request.user):
                return HttpResponseRedirect('/')
        return view_func(request, *args, **kwargs)
    return login_required(wraps(view_func)(_wrapped_view))

def to_list(func):
    @wraps(func)
    def f(*args, **kwargs):
        return list(func(*args, **kwargs))
    return f

def to_iter(func):
    @wraps(func)
    def f(*args, **kwargs):
        return utils.IterableFactory(lambda: func(*args, **kwargs))
    return f

def setting_enabled(name, settings=app_settings):
    '''Generate a decorator for enabling a view based on a setting'''
    def decorator(func):
        @wraps(func)
        def f(*args, **kwargs):
            if not getattr(settings, name, False):
                full_name = getattr(settings, 'prefix', '') + name
                raise Http404('enable %s' % full_name)
            return func(*args, **kwargs)
        return f
    return decorator
