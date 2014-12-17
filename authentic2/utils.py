import time
import hashlib
import datetime as dt
import logging
import urllib
import six

from importlib import import_module

from django.views.decorators.http import condition
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, HttpResponsePermanentRedirect
from django.core.exceptions import ImproperlyConfigured
from django.core import urlresolvers
from django.http.request import QueryDict
from django.contrib.auth import REDIRECT_FIELD_NAME

from authentic2.saml.saml2utils import filter_attribute_private_key, \
    filter_element_private_key

from . import plugins, app_settings, constants

class CleanLogMessage(logging.Filter):
    def filter(self, record):
        record.msg = filter_attribute_private_key(record.msg)
        record.msg = filter_element_private_key(record.msg)
        return True


class MWT(object):
    """Memoize With Timeout"""
    _caches = {}
    _timeouts = {}

    def __init__(self,timeout=2):
        self.timeout = timeout

    def collect(self):
        """Clear cache of results which have timed out"""
        for func in self._caches:
            cache = {}
            for key in self._caches[func]:
                if (time.time() - self._caches[func][key][1]) < self._timeouts[func]:
                    cache[key] = self._caches[func][key]
            self._caches[func] = cache

    def __call__(self, f):
        self.cache = self._caches[f] = {}
        self._timeouts[f] = self.timeout

        def func(*args, **kwargs):
            kw = kwargs.items()
            kw.sort()
            key = (args, tuple(kw))
            try:
                v = self.cache[key]
                if (time.time() - v[1]) > self.timeout:
                    raise KeyError
            except KeyError:
                v = self.cache[key] = f(*args,**kwargs),time.time()
            return v[0]
        func.func_name = f.func_name

        return func


def cache_and_validate(timeout, hashing=hashlib.md5):
    '''
       Decorator to add caching, with support for ETag and Last-modified
       validation.

       Just give it the time for caching.
    '''
    def transform(f):
        f.cache = dict()
        def get_content(request, *args, **kwargs):
            '''
               Content is kept as

                (last_generation_time, last_modified_time, etag, content)

               inside the f.cache dictionnary
            '''
            key=args+tuple(sorted(kwargs.items()))
            if request.method == 'PURGE' and request.environ.get('REMOTE_ADDR') \
                    in settings.INTERNAL_IPS:
                # purge the cache place
                f.cache.pop(key, None)
            now = dt.datetime.now()
            if key in f.cache:
                date, last_modified, etag, mime_type, old_content = f.cache[key]
                if now - date < dt.timedelta(seconds=timeout):
                    return date, last_modified, etag, mime_type, old_content
                else:
                    content = f(request, *args, **kwargs)
                    if old_content == content.content:
                        data = (now, last_modified, etag, mime_type, old_content)
                        return data
            else:
                content = f(request, *args, **kwargs)
            if content.status_code == 200:
                content_type = content.get('Content-Type', None)
                data = now, now, hashing(content.content).hexdigest(), content_type, content.content
                f.cache[key] = data
            else:
                data = None, None, None, None, content
            return data
        def get_last_modified(request, *args, **kwargs):
            _, last_modified, _, _, _ = get_content(request, *args, **kwargs)
            return last_modified
        def get_etag(request, *args, **kwargs):
            _, _, etag, _, _ = get_content(request, *args, **kwargs)
            return etag
        @condition(etag_func=get_etag, last_modified_func=get_last_modified)
        def replacement(request, *args, **kwargs):
            _, _, _, content_type, content = get_content(request, *args, **kwargs)
            if isinstance(content, six.string_types):
                return HttpResponse(content, content_type=content_type)
            else:
                return content
        return replacement
    return transform

def import_from(module, name):
    module = __import__(module, fromlist=[name])
    return getattr(module, name)

def get_session_store():
    return import_module(settings.SESSION_ENGINE).SessionStore

def flush_django_session(django_session_key):
    get_session_store()(session_key=django_session_key).flush()

class IterableFactory(object):
    '''Return an new iterable using a generator function each time this object
       is iterated.'''
    def __init__(self, f):
        self.f = f

    def __iter__(self):
        return iter(self.f())

def accumulate_from_backends(request, method_name):
    list = []
    for backend in get_backends():
        method = getattr(backend, method_name, None)
        if callable(method):
            list += method(request)
    # now try plugins
    for plugin in plugins.get_plugins():
        if hasattr(plugin, method_name):
            method = getattr(plugin, method_name)
            if callable(method):
                list += method(request)
    return list

def load_backend(path):
    '''Load an IdP backend by its module path'''
    i = path.rfind('.')
    module, attr = path[:i], path[i+1:]
    try:
        mod = import_module(module)
    except ImportError, e:
        raise ImproperlyConfigured('Error importing idp backend %s: "%s"' % (module, e))
    except ValueError, e:
        raise ImproperlyConfigured('Error importing idp backends. Is IDP_BACKENDS a correctly defined list or tuple?')
    try:
        cls = getattr(mod, attr)
    except AttributeError:
        raise ImproperlyConfigured('Module "%s" does not define a "%s" idp backend' % (module, attr))
    return cls()

def get_backends(setting_name='IDP_BACKENDS'):
    '''Return the list of IdP backends'''
    backends = []
    for backend_path in getattr(app_settings, setting_name):
        kwargs = {}
        if not isinstance(backend_path, six.string_types):
            backend_path, kwargs = backend_path
        backend = load_backend(backend_path)
        kwargs_settings = getattr(app_settings, setting_name + '_KWARGS', {})
        if backend_path in kwargs_settings:
            kwargs.update(kwargs_settings[backend_path])
        if hasattr(backend, 'id'):
            if hasattr(backend.id, '__call__'):
                bid = backend.id()
            else:
                bid = backend.id
            if bid in kwargs_settings:
                kwargs.update(kwargs_settings[bid])
        backend.__dict__.update(kwargs)
        backends.append(backend)
    return backends

def add_arg(url, key, value = None):
    '''Add a parameter to an URL'''
    key = urllib.quote(key)
    if value is not None:
        add = '%s=%s' % (key, urllib.quote(value))
    else:
        add = key
    if '?' in url:
        return '%s&%s' % (url, add)
    else:
        return '%s?%s' % (url, add)

def get_username(user):
    '''Retrieve the username from a user model'''
    if hasattr(user, 'USERNAME_FIELD'):
        return getattr(user, user.USERNAME_FIELD)
    else:
        return user.username

class Service(object):
    url = None
    name = None
    actions = []

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

def field_names(list_of_field_name_and_titles):
    for t in list_of_field_name_and_titles:
        if isinstance(t, six.string_types):
            yield t
        else:
            yield t[0]

# mostly copied from Django 1.7

def resolve_url(to, args=(), kwargs={}):
    '''Resolve a string to an URL, string can be a view callable, a view name
       or an absolute or relative URL.
    '''
    # If it's a model, use get_absolute_url()
    if hasattr(to, 'get_absolute_url'):
        return to.get_absolute_url()

    if isinstance(to, six.string_types):
        # Handle relative and absolute URLs
        if any(to.startswith(path) for path in ('./', '../')):
            return to

    # Next try a reverse URL resolution.
    try:
        return urlresolvers.reverse(to, args=args, kwargs=kwargs)
    except urlresolvers.NoReverseMatch:
        # If this is a callable, re-raise.
        if callable(to):
            raise
        # If this doesn't "feel" like a URL, re-raise.
        if '/' not in to and '.' not in to:
            raise

    # Finally, fall back and assume it's a URL
    return to

def make_url(to, args=(), kwargs={}, keep_params=False, params=None,
        append=None, request=None, include=None, exclude=None, fragment=None):
    '''Build an URL from a relative or absolute path, a model instance, a view
       name or view function.

       If you pass a request you can ask to keep params from it, exclude some
       of them or include only a subset of them.
       You can set parameters or append to existing one.
    '''
    url = resolve_url(to, *args, **kwargs)
    # Django < 1.6 compat, query_string is not optional
    url_params = QueryDict(query_string='', mutable=True)
    if keep_params:
        assert request is not None, 'missing request'
        for key, value in request.GET.iteritems():
            if exclude and key in exclude:
                continue
            if include and key not in include:
                continue
            url_params.setlist(key, request.GET.getlist(key))
    if params:
        for key, value in params.iteritems():
            if isinstance(value, (tuple, list)):
                url_params.setlist(key, value)
            else:
                url_params[key] = value
    if append:
        for key, value in append.iteritems():
            if isinstance(value, (tuple, list)):
                url_params.extend({key: value})
            else:
                url_params.appendlist(key, value)
    if url_params:
        url += '?%s' % url_params.urlencode()
    if fragment:
        url += '#%s' % fragment
    return url

# improvement over django.shortcuts.redirect

def redirect(request, to, args=(), kwargs={}, keep_params=False, params=None,
        append=None, include=None, exclude=None, permanent=False, fragment=None):
    '''Build a redirect response to an absolute or relative URL, eventually
       adding params from the request or new, see make_url().
    '''
    url = make_url(to, args=args, kwargs=kwargs, keep_params=keep_params, params=params,
            append=append, request=request, include=include, exclude=exclude, fragment=fragment)
    if permanent:
        redirect_class = HttpResponsePermanentRedirect
    else:
        redirect_class = HttpResponseRedirect
    return redirect_class(url)

def redirect_to_login(request, login_url='auth_login', keep_params=True,
        include=(REDIRECT_FIELD_NAME, constants.NONCE_FIELD_NAME),
        **kwargs):
    '''Redirect to the login, eventually adding a nonce'''
    return redirect(request, login_url, keep_params=keep_params,
            include=include, **kwargs)
