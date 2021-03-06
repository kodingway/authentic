import inspect
import random
import time
import logging
import urllib
import six
import urlparse
import uuid
import datetime
import copy

from functools import wraps
from itertools import islice, chain

from importlib import import_module

import django
from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http.request import QueryDict
from django.contrib.auth import (REDIRECT_FIELD_NAME, login as auth_login, SESSION_KEY,
                                 HASH_SESSION_KEY, BACKEND_SESSION_KEY, authenticate,
                                 get_user_model)
from django import forms
from django.forms.util import ErrorList
from django.forms.utils import to_current_timezone
from django.utils import timezone
from django.utils import html, http
from django.utils.translation import ugettext as _, ungettext
from django.shortcuts import resolve_url
from django.template.loader import render_to_string, TemplateDoesNotExist
from django.core.mail import send_mail
from django.core import signing
from django.core.urlresolvers import reverse, NoReverseMatch
from django.utils.formats import localize
from django.contrib import messages
from django.utils.functional import empty
from django.template import RequestContext
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.shortcuts import render


try:
    from django.core.exceptions import FieldDoesNotExist
except ImportError:
    # Django < 1.8
    from django.db.models.fields import FieldDoesNotExist

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

    def __init__(self, timeout=2):
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
                v = self.cache[key] = f(*args, **kwargs), time.time()
            return v[0]
        func.func_name = f.func_name

        return func


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


def accumulate_from_backends(request, method_name, **kwargs):
    list = []
    for backend in get_backends():
        method = getattr(backend, method_name, None)
        if callable(method):
            list += method(request, **kwargs)
    # now try plugins
    for plugin in plugins.get_plugins():
        if hasattr(plugin, method_name):
            method = getattr(plugin, method_name)
            if callable(method):
                list += method(request, **kwargs)
    return list


def load_backend(path):
    '''Load an IdP backend by its module path'''
    i = path.rfind('.')
    module, attr = path[:i], path[i + 1:]
    try:
        mod = import_module(module)
    except ImportError, e:
        raise ImproperlyConfigured('Error importing idp backend %s: "%s"' % (module, e))
    except ValueError, e:
        raise ImproperlyConfigured('Error importing idp backends. Is IDP_BACKENDS a correctly '
                                   'defined list or tuple?')
    try:
        cls = getattr(mod, attr)
    except AttributeError:
        raise ImproperlyConfigured('Module "%s" does not define a "%s" idp backend'
                                   % (module, attr))
    return cls()


def get_backends(setting_name='IDP_BACKENDS'):
    '''Return the list of enabled cleaned backends.'''
    backends = []
    for backend_path in getattr(app_settings, setting_name):
        kwargs = {}
        if not isinstance(backend_path, six.string_types):
            backend_path, kwargs = backend_path
        backend = load_backend(backend_path)
        # If no enabled method is defined on the backend, backend enabled by default.
        if hasattr(backend, 'enabled') and not backend.enabled():
            continue
        kwargs_settings = getattr(app_settings, setting_name + '_KWARGS', {})
        if backend_path in kwargs_settings:
            kwargs.update(kwargs_settings[backend_path])
        # Clean id and name for legacy support
        if hasattr(backend, 'id'):
            if callable(backend.id):
                backend.id = backend.id()
        else:
            backend.id = None
        if hasattr(backend, 'name'):
            if callable(backend.name):
                backend.name = backend.name()
        else:
            backend.name = None
        if not hasattr(backend, 'priority'):
            backend.priority = 0
        if backend.id and backend.id in kwargs_settings:
            kwargs.update(kwargs_settings[backend.id])
        backend.__dict__.update(kwargs)
        backends.append(backend)
    # Order backends list with backend priority
    backends.sort(key=lambda backend: backend.priority)
    return backends


def get_backend_method(backend, method, parameters):
    if not hasattr(backend, method):
        return None
    content = response = getattr(backend, method)(**parameters)
    if not response:
        return None
    status_code = 200
    # Some backend methods return an HttpResponse, others return a string
    if isinstance(response, HttpResponse):
        content = response.content
        status_code = response.status_code
    return {
            'id': backend.id,
            'name': backend.name,
            'content': content,
            'response': response,
            'status_code': status_code,
            'backend': backend,
    }


def add_arg(url, key, value=None):
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


def is_valid_url(url):
    try:
        parsed = urlparse.urlparse(url)
        if parsed.scheme in ('http', 'https', ''):
            return True
    except:
        return False


def make_url(to, args=(), kwargs={}, keep_params=False, params=None, append=None, request=None,
             include=None, exclude=None, fragment=None, absolute=False, resolve=True):
    '''Build an URL from a relative or absolute path, a model instance, a view
       name or view function.

       If you pass a request you can ask to keep params from it, exclude some
       of them or include only a subset of them.
       You can set parameters or append to existing one.
    '''
    if resolve:
        url = resolve_url(to, *args, **kwargs)
    else:
        url = to
    scheme, netloc, path, query_string, o_fragment = urlparse.urlsplit(url)
    url = urlparse.urlunsplit((scheme, netloc, path, '', ''))
    fragment = fragment or o_fragment
    # Django < 1.6 compat, query_string is not optional
    url_params = QueryDict(query_string=query_string, mutable=True)
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
        url += '?%s' % url_params.urlencode(safe='/')
    if fragment:
        url += '#%s' % fragment
    if absolute:
        if request:
            url = request.build_absolute_uri(url)
        else:
            raise TypeError('make_url() absolute cannot be used without request')
    return url


# improvement over django.shortcuts.redirect
def redirect(request, to, args=(), kwargs={}, keep_params=False, params=None,
             append=None, include=None, exclude=None, permanent=False,
             fragment=None, status=302, resolve=True):
    '''Build a redirect response to an absolute or relative URL, eventually
       adding params from the request or new, see make_url().
    '''
    url = make_url(to, args=args, kwargs=kwargs, keep_params=keep_params,
                   params=params, append=append, request=request,
                   include=include, exclude=exclude, fragment=fragment, resolve=resolve)
    if permanent:
        status = 301
    return HttpResponseRedirect(url, status=status)


def redirect_to_login(request, login_url='auth_login', keep_params=True,
                      include=(REDIRECT_FIELD_NAME, constants.NONCE_FIELD_NAME), **kwargs):
    '''Redirect to the login, eventually adding a nonce'''
    return redirect(request, login_url, keep_params=keep_params, include=include, **kwargs)


def continue_to_next_url(request, keep_params=True, include=(constants.NONCE_FIELD_NAME,),
                         **kwargs):
    next_url = request.POST.get(REDIRECT_FIELD_NAME)
    next_url = next_url or request.GET.get(REDIRECT_FIELD_NAME)
    next_url = next_url or settings.LOGIN_REDIRECT_URL
    return redirect(request, to=next_url, keep_params=keep_params, include=include, **kwargs)


def get_nonce(request):
    nonce = request.GET.get(constants.NONCE_FIELD_NAME)
    if request.method == 'POST':
        nonce = request.POST.get(constants.NONCE_FIELD_NAME, nonce)
    return nonce


def record_authentication_event(request, how):
    '''Record an authentication event in the session and in the database, in
       later version the database persistence can be removed'''
    from . import models
    logging.getLogger(__name__).info('logged in (%s)', how)
    authentication_events = request.session.setdefault(constants.AUTHENTICATION_EVENTS_SESSION_KEY,
                                                       [])
    # As we update a persistent object and not a session key we must
    # explicitly state that the session has been modified
    request.session.modified = True
    event = {
        'who': unicode(request.user),
        'who_id': getattr(request.user, 'pk', None),
        'how': how,
        'when': int(time.time()),

    }
    kwargs = {
        'who': unicode(request.user)[:80],
        'how': how,
    }
    nonce = get_nonce(request)
    if nonce:
        kwargs['nonce'] = nonce
        event['nonce'] = nonce
    authentication_events.append(event)

    models.AuthenticationEvent.objects.create(**kwargs)


def find_authentication_event(request, nonce):
    '''Find an authentication event occurring during this session and matching
       this nonce.'''
    authentication_events = request.session.get(constants.AUTHENTICATION_EVENTS_SESSION_KEY, [])
    for event in authentication_events:
        if event.get('nonce') == nonce:
            return event
    return None


def last_authentication_event(session):
    authentication_events = session.get(constants.AUTHENTICATION_EVENTS_SESSION_KEY, [])
    if authentication_events:
        return authentication_events[-1]
    return None


def login(request, user, how, **kwargs):
    '''Login a user model, record the authentication event and redirect to next
       URL or settings.LOGIN_REDIRECT_URL.'''
    last_login = user.last_login
    auth_login(request, user)
    if hasattr(user, 'init_to_session'):
        user.init_to_session(request.session)
    if constants.LAST_LOGIN_SESSION_KEY not in request.session:
        request.session[constants.LAST_LOGIN_SESSION_KEY] = \
            localize(to_current_timezone(last_login), True)
    record_authentication_event(request, how)
    return continue_to_next_url(request, **kwargs)


def login_require(request, next_url=None, login_url='auth_login', **kwargs):
    '''Require a login and come back to current URL'''
    next_url = next_url or request.get_full_path()
    params = kwargs.setdefault('params', {})
    params[REDIRECT_FIELD_NAME] = next_url
    return redirect(request, login_url, **kwargs)


def redirect_to_logout(request, next_url=None, logout_url='auth_logout', **kwargs):
    '''Redirect to the logout and come back to the current page.'''
    next_url = next_url or request.get_full_path()
    params = kwargs.setdefault('params', {})
    params[REDIRECT_FIELD_NAME] = next_url
    return redirect(request, logout_url, **kwargs)


def redirect_and_come_back(request, to, **kwargs):
    '''Redirect to a view adding current URL as next URL parameter'''
    next_url = request.get_full_path()
    params = kwargs.setdefault('params', {})
    params[REDIRECT_FIELD_NAME] = next_url
    return redirect(request, to, **kwargs)


def generate_password():
    '''Generate a password based on a certain composition based on number of
       characters based on classes of characters.
    '''
    composition = ((2, '23456789'),
                   (6, 'ABCDEFGHJKLMNPQRSTUVWXYZ'),
                   (1, '%$/\\#@!'))
    parts = []
    for count, alphabet in composition:
        for i in range(count):
            parts.append(random.SystemRandom().choice(alphabet))
    random.shuffle(parts, random.SystemRandom().random)
    return ''.join(parts)


def form_add_error(form, msg, safe=False):
    # without this line form._errors is not initialized
    form.errors
    errors = form._errors.setdefault(forms.forms.NON_FIELD_ERRORS, ErrorList())
    if safe:
        msg = html.mark_safe(msg)
    errors.append(msg)


def import_module_or_class(path):
    try:
        return import_module(path)
    except ImportError:
        try:
            module, attr = path.rsplit('.', 1)
            source = import_module(module)
            return getattr(source, attr)
        except (ImportError, AttributeError):
            raise ImproperlyConfigured('unable to import class/module path: %r' % path)


def check_referer(request, skip_post=True):
    '''Check that the current referer match current origin.

       Post requests are usually ignored as they are already check by the
       CSRF middleware.
    '''
    if skip_post and request.method == 'POST':
        return True
    referer = request.META.get('HTTP_REFERER')
    return referer and same_origin(request.build_absolute_uri(), referer)


def check_session_key(session_key):
    '''Check that a session exists for a given session_key.'''
    from importlib import import_module
    from django.conf import settings

    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    s = SessionStore(session_key=session_key)
    # If session is empty, it's new
    return s._session != {}


def get_user_from_session_key(session_key):
    '''Get the user logged in an active session'''
    from importlib import import_module
    from django.conf import settings
    from django.contrib.auth import (load_backend, SESSION_KEY, BACKEND_SESSION_KEY)
    from django.contrib.auth.models import AnonymousUser

    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    session = SessionStore(session_key=session_key)
    try:
        user_id = session[SESSION_KEY]
        backend_path = session[BACKEND_SESSION_KEY]
        assert backend_path in settings.AUTHENTICATION_BACKENDS
        backend = load_backend(backend_path)
        if 'session' in inspect.getargspec(backend.get_user)[0]:
            user = backend.get_user(user_id, session) or AnonymousUser()
        else:
            user = backend.get_user(user_id) or AnonymousUser()
    except (KeyError, AssertionError):
        user = AnonymousUser()
    return user


def to_list(func):
    @wraps(func)
    def f(*args, **kwargs):
        return list(func(*args, **kwargs))
    return f


def to_iter(func):
    @wraps(func)
    def f(*args, **kwargs):
        return IterableFactory(lambda: func(*args, **kwargs))
    return f


def normalize_attribute_values(values):
    '''Take a list of values or a single one and normalize it'''
    values_set = set()
    if isinstance(values, basestring) or not hasattr(values, '__iter__'):
        values = [values]
    for value in values:
        if isinstance(value, bool):
            value = str(value).lower()
        values_set.add(unicode(value))
    return values_set


def attribute_values_to_identifier(values):
    '''Try to find an identifier from attribute values'''
    normalized = normalize_attribute_values(values)
    assert len(normalized) == 1, 'multi-valued attribute cannot be used as an identifier'
    return list(normalized)[0]


def csrf_token_check(request, form):
    '''Check a request for CSRF cookie validation, and add an error to the form
       if check fails.
    '''
    # allow tests to disable csrf check
    if form.is_valid() and not getattr(request, 'csrf_processing_done', False):
        msg = _('The form was out of date, please try again.')
        form._errors[forms.forms.NON_FIELD_ERRORS] = ErrorList([msg])


def get_hex_uuid():
    return uuid.uuid4().get_hex()


def get_fields_and_labels(*args):
    '''Analyze fields settings and extracts ordered list of fields and
       their overriden labels.
    '''
    labels = {}
    fields = []
    for arg in args:
        for field in arg:
            if isinstance(field, (list, tuple)):
                field, label = field
                labels[field] = label
            if not field in fields:
                fields.append(field)
    return fields, labels


def send_templated_mail(user_or_email, template_names, context=None, with_html=True,
                        from_email=None, request=None, legacy_subject_templates=None,
                        legacy_body_templates=None, legacy_html_body_templates=None, **kwargs):
    '''Send mail to an user by using templates:
       - <template_name>_subject.txt for the subject
       - <template_name>_body.txt for the plain text body
       - <template_name>_body.html for the HTML body
    '''
    from . import middleware
    if isinstance(template_names, basestring):
        template_names = [template_names]
    if hasattr(user_or_email, 'email'):
        user_or_email = user_or_email.email
    if not request:
        request = middleware.StoreRequestMiddleware().get_request()
    if request:
        ctx = RequestContext(request)
        ctx.update(context or {})
    else:
        ctx = context or {}

    subject_template_names = [template_name + '_subject.txt' for template_name in template_names]
    subject_template_names += legacy_subject_templates or []
    subject = render_to_string(subject_template_names, ctx).strip()

    body_template_names = [template_name + '_body.txt' for template_name in template_names]
    body_template_names += legacy_body_templates or []
    body = render_to_string(body_template_names, ctx)

    html_body = None
    html_body_template_names = [template_name + '_body.html' for template_name in template_names]
    html_body_template_names += legacy_html_body_templates or []
    if with_html:
        try:
            html_body = render_to_string(html_body_template_names, ctx)
        except TemplateDoesNotExist:
            html_body = None
    send_mail(subject, body, from_email or settings.DEFAULT_FROM_EMAIL, [user_or_email],
              html_message=html_body, **kwargs)


if django.VERSION < (1, 8, 0):
    from django.db.models import ForeignKey

    def get_fk_model(model, fieldname):
        '''returns None if not foreignkey, otherswise the relevant model'''
        try:
            field_object, model, direct, m2m = model._meta.get_field_by_name(fieldname)
        except FieldDoesNotExist:
            return None
        if not m2m and direct and isinstance(field_object, ForeignKey):
            return field_object.rel.to
        return None
else:
    def get_fk_model(model, fieldname):
        try:
            field = model._meta.get_field('ou')
        except FieldDoesNotExist:
            return None
        else:
            if not field.is_relation or not field.many_to_one:
                return None
            return field.related_model


def get_registration_url(request):
    if REDIRECT_FIELD_NAME in request.GET and is_valid_url(request.GET[REDIRECT_FIELD_NAME]):
        next_url = request.GET.get(REDIRECT_FIELD_NAME)
    else:
        next_url = make_url(settings.LOGIN_REDIRECT_URL)
    next_url = make_url(next_url, request=request, keep_params=True,
                        include=(constants.NONCE_FIELD_NAME,), resolve=False)
    return make_url('registration_register',
                    params={REDIRECT_FIELD_NAME: next_url})


def build_activation_url(request, email, next_url=None, **kwargs):
    data = kwargs.copy()
    data['email'] = email
    data[REDIRECT_FIELD_NAME] = next_url
    registration_token = signing.dumps(data)
    activate_url = request.build_absolute_uri(
        reverse('registration_activate', kwargs={'registration_token': registration_token}))
    return activate_url


def send_registration_mail(request, email, ou, template_names=None, next_url=None, context=None,
                           **kwargs):
    '''Send a registration mail to an user. All given kwargs will be used
       to completed the user model.

       Can raise an smtplib.SMTPException
    '''
    logger = logging.getLogger(__name__)
    User = get_user_model()

    if not template_names:
        template_names = ['authentic2/activation_email']

    # registration_url
    registration_url = build_activation_url(request, email=email, next_url=next_url, ou=ou.pk,
                                            **kwargs)

    # existing accounts
    existing_accounts = User.objects.filter(email=email)
    if not app_settings.A2_EMAIL_IS_UNIQUE:
        existing_accounts = existing_accounts.filter(ou=ou, email=email)

    # ctx for rendering the templates
    context = context or {}
    context.update({
        'registration_url': registration_url,
        'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
        'email': email,
        'site': request.get_host(),
        'existing_accounts': existing_accounts,
    })

    send_templated_mail(email, template_names,
                        request=request,
                        context=context,
                        # legacy templates, for new templates use
                        # authentic2/activation_email_body.txt
                        # authentic2/activation_email_body.html
                        # authentic2/activation_email_subject.txt
                        legacy_subject_templates=['registration/activation_email_subject.txt'],
                        legacy_body_templates=['registration/activation_email.txt'],
                        legacy_html_body_templates=['registration/activation_email.html'])
    logger.info(u'registration mail sent to  %s with registration URL %s...', email,
                registration_url)


def build_reset_password_url(user, request=None, next_url=None, set_random_password=True):
    '''Build a reset password URL'''
    from .compat import default_token_generator

    if set_random_password:
        user.set_password(uuid.uuid4().hex)
        user.save()
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    reset_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
    if request:
        reset_url = request.build_absolute_uri(reset_url)
    if next_url:
        reset_url += '?' + urllib.urlencode({'next': next_url})
    return reset_url, token


def send_password_reset_mail(user, template_names=None, request=None,
                             token_generator=None, from_email=None,
                             next_url=None, context=None,
                             legacy_subject_templates=['registration/password_reset_subject.txt'],
                             legacy_body_templates=['registration/password_reset_email.html'],
                             set_random_password=True,
                             **kwargs):
    from . import middleware

    if not user.email:
        raise ValueError('user must have an email')
    logger = logging.getLogger(__name__)
    if not template_names:
        template_names = 'authentic2/password_reset_email'
    if not request:
        request = middleware.StoreRequestMiddleware().get_request()

    ctx = {}
    ctx.update(context or {})
    ctx.update({
        'user': user,
        'email': user.email,
        'expiration_days': settings.PASSWORD_RESET_TIMEOUT_DAYS,
    })

    # Build reset URL
    ctx['reset_url'], token = build_reset_password_url(user, request=request, next_url=next_url,
                                                       set_random_password=set_random_password)

    send_templated_mail(user.email, template_names, ctx, request=request,
                        legacy_subject_templates=legacy_subject_templates,
                        legacy_body_templates=legacy_body_templates, **kwargs)
    logger.info(u'password reset requests for %s, email sent to %s '
                'with token %s...', user, user.email, token[:9])


def batch(iterable, size):
    '''Batch an iterable as an iterable of iterables of at most size element
       long.
    '''
    sourceiter = iter(iterable)
    while True:
        batchiter = islice(sourceiter, size)
        yield chain([batchiter.next()], batchiter)


def lower_keys(d):
    '''Convert all keys in dictionary d to lowercase'''
    return dict((key.lower(), value) for key, value in d.iteritems())


def to_dict_of_set(d):
    '''Convert a dictionary of sequence into a dictionary of sets'''
    return dict((k, set(v)) for k, v in d.iteritems())


def switch_user(request, new_user):
    '''Switch to another user and remember currently logged in user in the
       session. Reserved to superusers.'''
    logger = logging.getLogger(__name__)
    if constants.SWITCH_USER_SESSION_KEY in request.session:
        messages.error(request, _('Your user is already switched, go to your '
                                  'account page and come back to your original '
                                  'user to do it again.'))
    else:
        if not request.user.is_superuser:
            raise PermissionDenied
        switched = {}
        for key in (SESSION_KEY, BACKEND_SESSION_KEY, HASH_SESSION_KEY,
                    constants.LAST_LOGIN_SESSION_KEY):
            switched[key] = request.session[key]
        user = authenticate(user=new_user)
        login(request, user, 'switch')
        request.session[constants.SWITCH_USER_SESSION_KEY] = switched
        if constants.LAST_LOGIN_SESSION_KEY not in request.session:
            request.session[constants.LAST_LOGIN_SESSION_KEY] = \
                localize(to_current_timezone(new_user.last_login), True)
        messages.info(request, _('Successfully switched to user %s') %
                      new_user.get_full_name())
        logger.info(u'switched to user %s', new_user)
        return continue_to_next_url(request)


def switch_back(request):
    '''Switch back to original superuser after a user switch'''
    logger = logging.getLogger(__name__)
    if constants.SWITCH_USER_SESSION_KEY in request.session:
        switched = request.session[constants.SWITCH_USER_SESSION_KEY]
        for key in switched:
            request.session[key] = switched[key]
        del request.session[constants.SWITCH_USER_SESSION_KEY]
        del request._cached_user
        request.user._wrapped = empty
        messages.info(request, _('Successfully switched back to user %s')
                      % request.user.get_full_name())
        logger.info(u'switched back to user %s', request.user)
    else:
        messages.warning(request, _('No user to switch back to'))
    return continue_to_next_url(request)


def datetime_to_utc(dt):
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return dt.astimezone(timezone.utc)


def datetime_to_xs_datetime(dt):
    return datetime_to_utc(dt).isoformat().split('.')[0] + 'Z'


def utf8_encode(v):
    if isinstance(v, dict):
        return dict((utf8_encode(a), utf8_encode(b)) for a, b in v.iteritems())
    if isinstance(v, (list, tuple)):
        return type(v)(utf8_encode(a) for a in v)
    if isinstance(v, unicode):
        return v.encode('utf-8')
    return v


def good_next_url(request, next_url):
    '''Check if an URL is a good next_url'''
    if not next_url:
        return False
    if (next_url.startswith('/') and (len(next_url) == 1 or next_url[1] != '/')):
        return True
    if same_origin(request.build_absolute_uri(), next_url):
        return True
    for origin in app_settings.A2_REDIRECT_WHITELIST:
        if same_origin(next_url, origin):
            return True
    return False


def select_next_url(request, default):
    '''Select the first valid next URL'''
    next_url = request.GET.get(REDIRECT_FIELD_NAME)
    if good_next_url(request, next_url):
        return next_url
    return default


def timestamp_from_datetime(dt):
    '''Convert an aware datetime as an Unix timestamp'''
    utc_naive = dt.replace(tzinfo=None) - dt.utcoffset()
    return int((utc_naive - datetime.datetime(1970, 1, 1)).total_seconds())


def human_duration(seconds):
    day = (24 * 3600)
    hour = 3600
    minute = 60
    days, seconds = seconds // day, seconds % day
    hours, seconds = seconds // hour, seconds % hour
    minutes, seconds = seconds // minute, seconds % minute

    s = []
    if days:
        s.append(ungettext('%s day', '%s days', days) % days)
    if hours:
        s.append(ungettext('%s hour', '%s hours', hours) % hours)
    if minutes:
        s.append(ungettext('%s minute', '%s minutes', minutes) % minutes)
    if seconds:
        s.append(ungettext('%s second', '%s seconds', seconds) % seconds)
    return ', '.join(s)


class ServiceAccessDenied(Exception):

    def __init__(self, service):
        self.service = service


def unauthorized_view(request, service):
    context = {'callback_url': service.unauthorized_url or reverse('a2-homepage')}
    return render(request, 'authentic2/unauthorized.html', context=context)


PROTOCOLS_TO_PORT = {
    'http': '80',
    'https': '443',
}


def netloc_to_host_port(netloc):
    if not netloc:
        return None, None
    splitted = netloc.split(':', 1)
    if len(splitted) > 1:
        return splitted[0], splitted[1]
    return splitted[0], None


def same_domain(domain1, domain2):
    if domain1 == domain2:
        return True

    if domain2.startswith('.'):
        # p1 is a sub-domain or the base domain
        if domain1.endswith(domain2) or domain1 == domain2[1:]:
            return True
    return False


def same_origin(url1, url2):
    '''Checks if both URL use the same domain. It understands domain patterns on url2, i.e. .example.com
    matches www.example.com.

    If not scheme is given in url2, scheme compare is skipped.
    If not scheme and not port are given, port compare is skipped.
    The last two rules allow authorizing complete domains easily.
    '''
    p1, p2 = urlparse.urlparse(url1), urlparse.urlparse(url2)
    p1_host, p1_port = netloc_to_host_port(p1.netloc)
    p2_host, p2_port = netloc_to_host_port(p2.netloc)

    if p2.scheme and p1.scheme != p2.scheme:
        return False

    if not same_domain(p1_host, p2_host):
        return False

    try:
        if (p2_port or (p1_port and p2.scheme)) and (
                (p1_port or PROTOCOLS_TO_PORT[p1.scheme])
                != (p2_port or PROTOCOLS_TO_PORT[p2.scheme])):
            return False
    except (ValueError, KeyError):
        return False

    return True


def simulate_authentication(request, user, method,
                            backend='authentic2.backends.models_backend.ModelBackend', **kwargs):
    '''Simulate a normal login by forcing a backend attribute on the user instance'''
    # do not modify the passed user
    user = copy.deepcopy(user)
    user.backend = backend
    return login(request, user, method, **kwargs)


def get_manager_login_url():
    from authentic2.manager import app_settings
    return app_settings.LOGIN_URL or settings.LOGIN_URL
