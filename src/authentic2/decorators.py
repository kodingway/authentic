from django.contrib.auth.decorators import login_required
from django.views.debug import technical_404_response
from django.http import Http404
from functools import wraps

from . import utils, app_settings
from .utils import to_list, to_iter

TRANSIENT_USER_TYPES = []

def is_transient_user(user):
    return isinstance(user, tuple(TRANSIENT_USER_TYPES))

def prevent_access_to_transient_users(view_func):
    def _wrapped_view(request, *args, **kwargs):
        '''Test if the user is transient'''
        for user_type in TRANSIENT_USER_TYPES:
            if is_transient_user(request.user):
                return utils.continue_to_next_url(request, keep_params=False)
        return view_func(request, *args, **kwargs)
    return login_required(wraps(view_func)(_wrapped_view))

def unless(test, message):
    '''Decorator returning a 404 status code if some condition is not met'''
    def decorator(func):
        @wraps(func)
        def f(request, *args, **kwargs):
            if not test():
                return technical_404_response(request, Http404(message))
            return func(request, *args, **kwargs)
        return f
    return decorator

def setting_enabled(name, settings=app_settings):
    '''Generate a decorator for enabling a view based on a setting'''
    full_name = getattr(settings, 'prefix', '') + name
    def test():
        return getattr(settings, name, False)
    return unless(test, 'please enable %s' % full_name)

def lasso_required():
    def test():
        try:
            import lasso
            return True
        except ImportError:
            return False
    return unless(test, 'please install lasso')

def required(wrapping_functions,patterns_rslt):
    '''
    Used to require 1..n decorators in any view returned by a url tree

    Usage:
      urlpatterns = required(func,patterns(...))
      urlpatterns = required((func,func,func),patterns(...))

    Note:
      Use functools.partial to pass keyword params to the required 
      decorators. If you need to pass args you will have to write a 
      wrapper function.

    Example:
      from functools import partial

      urlpatterns = required(
          partial(login_required,login_url='/accounts/login/'),
          patterns(...)
      )
    '''
    if not hasattr(wrapping_functions,'__iter__'): 
        wrapping_functions = (wrapping_functions,)

    return [
        _wrap_instance__resolve(wrapping_functions,instance)
        for instance in patterns_rslt
    ]

def _wrap_instance__resolve(wrapping_functions,instance):
    if not hasattr(instance,'resolve'): return instance
    resolve = getattr(instance,'resolve')

    def _wrap_func_in_returned_resolver_match(*args,**kwargs):
        rslt = resolve(*args,**kwargs)

        if not hasattr(rslt,'func'):return rslt
        f = getattr(rslt,'func')

        for _f in reversed(wrapping_functions):
            # @decorate the function from inner to outter
            f = _f(f)

        setattr(rslt,'func',f)

        return rslt

    setattr(instance,'resolve',_wrap_func_in_returned_resolver_match)

    return instance
