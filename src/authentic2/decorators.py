import pickle
from contextlib import contextmanager
import time
from functools import wraps

from django.contrib.auth.decorators import login_required
from django.views.debug import technical_404_response
from django.http import Http404
from django.core.cache import cache as django_cache

from . import utils, app_settings, middleware
from .utils import to_list, to_iter

TRANSIENT_USER_TYPES = []

class CacheUnusable(RuntimeError):
    pass

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

class CacheDecoratorBase(object):
    '''Base class to build cache decorators.

       It helps for building keys from function arguments.
    '''
    def __new__(cls, *args, **kwargs):
        if len(args) > 1:
            raise TypeError('%s got unexpected arguments, only one argument '
                    'must be given, the function to decorate' % cls.__name__)
        if args:
            # Case of a decorator used directly
            return cls(**kwargs)(args[0])
        return super(CacheDecoratorBase, cls).__new__(cls, *args, **kwargs)

    def __init__(self, timeout=None, hostname_vary=True, args=None,
                 kwargs=None):
        self.timeout = timeout
        self.hostname_vary = hostname_vary
        self.args = args
        self.kwargs = kwargs

    def set(self, key, value):
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError

    def __call__(self, func):
        @wraps(func)
        def f(*args, **kwargs):
            try:
                now = time.time()
                key = self.key(*args, **kwargs)
                value, tstamp = self.get(key)
                if tstamp is not None:
                    if self.timeout is None or \
                       tstamp + self.timeout > now:
                           return value
                    if hasattr(self, 'delete'):
                        self.delete(key, (key, tstamp))
                value = func(*args, **kwargs)
                self.set(key, (value, now))
                return value
            except CacheUnusable: # fallback when cache cannot be used
                return func(*args, **kwargs)
        return f

    def key(self, *args, **kwargs):
        '''Transform arguments to string and build a key from it'''
        parts = [str(id(self))] # add cache instance to the key
        if self.hostname_vary:
            request = middleware.StoreRequestMiddleware.get_request()
            if request:
                parts.append(request.get_host())
            else: 
                # if we cannot determine the hostname it's better to ignore the
                # cache
                raise CacheUnusable
        for i, arg in enumerate(args):
            if self.args and i not in self.args:
                continue
            parts.append(unicode(arg))

        for kw, arg in sorted(kwargs.iteritems(), key=lambda x: x[0]):
            if self.kwargs in kw not in self.kwargs:
                continue
            parts.append(u'%s-%s' % (unicode(kw), unicode(arg)))
        return u'|'.join(parts)

class SimpleDictionnaryCacheMixin(object):
    '''Default implementations of set, get and delete for a cache implemented
       using a dictionary. The dictionnary must be returned by a property named
       'cache'.
    '''
    def set(self, key, value):
        self.cache[key] = value

    def get(self, key):
        return self.cache.get(key, (None, None))

    def delete(self, key, value):
        if key in self.cache and self.cache[key] == value:
            del self.cache[key]


class GlobalCache(SimpleDictionnaryCacheMixin, CacheDecoratorBase):
    def __init__(self, *args, **kwargs):
        self.cache = {}
        super(GlobalCache, self).__init__(*args, **kwargs)


class RequestCache(SimpleDictionnaryCacheMixin, CacheDecoratorBase):
    @property
    def cache(self):
        request = middleware.StoreRequestMiddleware.get_request()
        if not request:
            return {}
        # create a cache dictionary on the request
        return request.__dict__.setdefault(self.__class__.__name__, {})

class DjangoCache(SimpleDictionnaryCacheMixin, CacheDecoratorBase):
    @property
    def cache(self):
        return django_cache

    def set(self, key, value):
        self.cache.set(key, value, timeout=self.timeout)

    def delete(self, key, value):
        if self.get(key) == value:
            self.delete(key)


class PickleCacheMixin(object):
    def set(self, key, value):
        value, tstamp = value
        value = pickle.dumps(value)
        super(PickleCacheMixin, self).set(key, (value, tstamp))

    def get(self, key):
        value = super(PickleCacheMixin, self).get(key)
        if value[0] is not None:
            value = (pickle.loads(value[0]), value[1])
        return value


class SessionCache(PickleCacheMixin, SimpleDictionnaryCacheMixin,
                   CacheDecoratorBase):
    @property
    def cache(self):
        request = middleware.StoreRequestMiddleware.get_request()
        if not request:
            return {}
        # create a cache dictionary on the request
        return request.session.setdefault(self.__class__.__name__, {})


@contextmanager
def errorcollector(error_dict):
    try:
        yield
    except ValidationError, e:
        e.update_error_dict(error_dict)
