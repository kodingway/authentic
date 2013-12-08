import urllib
import logging

from django.utils.translation import ugettext as _
from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.models import SiteProfileNotAvailable
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.core.exceptions import ObjectDoesNotExist

from authentic2.idp import get_backends
from authentic2.authsaml2.models import SAML2TransientUser

from authentic2 import app_settings

logger = logging.getLogger('authentic2.idp.views')

__logout_redirection_timeout = getattr(settings, 'IDP_LOGOUT_TIMEOUT', 600)

def accumulate_from_backends(request, method_name):
    list = []
    for backend in get_backends():
        method = getattr(backend, method_name, None)
        if callable(method):
            list += method(request)
    return list

def service_list(request):
    '''Compute the service list to show on user homepage'''
    return accumulate_from_backends(request, 'service_list')

def homepage(request):
    '''Homepage of the IdP'''
    tpl_parameters = {}
    if not isinstance(request.user, SAML2TransientUser):
        tpl_parameters['account_management'] = 'account_management'
        tpl_parameters['authorized_services'] = service_list(request)
    return render_to_response('idp/homepage.html',
       tpl_parameters, RequestContext(request))

def profile(request):

    frontends = get_backends('AUTH_FRONTENDS')

    if request.method == "POST":
        for frontend in frontends:
            if not frontend.enabled():
                continue
            if 'submit-%s' % frontend.id() in request.POST:
                form = frontend.form()(data=request.POST)
                if form.is_valid():
                    if request.session.test_cookie_worked():
                        request.session.delete_test_cookie()
                    return frontend.post(request, form, None, '/profile')
    # User attributes management
    profile = []
    try:
        for field_name in getattr(request.user, 'USER_PROFILE', []):
            if isinstance(field_name, tuple):
                field_name, title = field_name
            elif isinstance(field_name, str):
                title = request.user._meta.get_field(field_name).verbose_name
            else:
                raise TypeError('USER_PROFILE must contain string or tuple')
            value = getattr(request.user, field_name, None)
            if not value:
                continue
            if callable(value):
                value = value()
            if not isinstance(value, basestring) and hasattr(value, '__iter__'):
                profile.append((title, map(unicode, value)))
            else:
                profile.append((title, [unicode(value)]))
    except (SiteProfileNotAvailable, ObjectDoesNotExist):
        pass
    # Credentials management
    blocks = [ frontend.profile(request, next='/profile') for frontend in frontends \
            if hasattr(frontend, 'profile') ]
    return render_to_response('idp/account_management.html', {
        'frontends_block': blocks,
        'profile': profile,
        'allow_account_deletion': app_settings.A2_REGISTRATION_CAN_DELETE_ACCOUNT,
        },
        RequestContext(request))

def logout_list(request):
    '''Return logout links from idp backends'''
    return accumulate_from_backends(request, 'logout_list')

def logout(request, next_page='/', redirect_field_name=REDIRECT_FIELD_NAME,
        template = 'idp/logout.html'):
    global __logout_redirection_timeout
    "Logs out the user and displays 'You are logged out' message."
    do_local = 'local' in request.REQUEST
    context = RequestContext(request)
    context['redir_timeout'] = __logout_redirection_timeout
    next_page = request.REQUEST.get(redirect_field_name, next_page)
    if not do_local:
        l = logout_list(request)
        if l:
            # Full logout
            next_page = '/logout?local=ok&next=%s' % urllib.quote(next_page)
            context['logout_list'] = l
            logger.debug('logout: %r' % unicode(context['logout_list']))
            context['next_page'] = next_page
            context['message'] = _('Logging out from all your services')
            return render_to_response(template, context_instance = context)
    # Local logout
    auth_logout(request)
    context['next_page'] = next_page
    context['message'] = _('Logged out')
    return render_to_response(template, context_instance = context)

def redirect_to_logout(request, next_page='/'):
    return HttpResponseRedirect('%s?next=%s' % (reverse(logout), urllib.quote(next_page)))
