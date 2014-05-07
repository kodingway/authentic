import functools
import logging
import urllib


from django.conf import settings
from django.core.urlresolvers import reverse
from django.utils.translation import ugettext as _
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response, redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import TemplateView
from django.template import RequestContext
from django.template.loader import render_to_string
from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login
from django.contrib.auth import REDIRECT_FIELD_NAME


import registration.views


from authentic2.constants import NONCE_FIELD_NAME
from authentic2.decorators import prevent_access_to_transient_users

from . import forms, models, util, app_settings

logger = logging.getLogger(__name__)

def get_next(request):
    next_url = request.REQUEST.get(REDIRECT_FIELD_NAME)
    if not next_url:
        if 'next' in request.session:
            next_url = request.session['next']
        elif settings.LOGIN_REDIRECT_URL:
            next_url = settings.LOGIN_REDIRECT_URL
        else:
            next_url = '/'
    return next_url

def handle_request(request):
    next_url = get_next(request)

    # Check certificate validity
    ssl_info  = util.SSLInfo(request)
    accept_self_signed = app_settings.ACCEPT_SELF_SIGNED

    if not ssl_info.cert:
        logger.error('SSL Client Authentication failed: '
            'SSL CGI variable CERT is missing')
        messages.add_message(request, messages.ERROR,
            _('SSL Client Authentication failed. '
            'No client certificate found.'))
        return redirect_to_login(next_url)
    elif not accept_self_signed and not ssl_info.verify:
        logger.error('SSL Client Authentication failed: '
            'SSL CGI variable VERIFY is not SUCCESS')
        messages.add_message(request, messages.ERROR,
            _('SSL Client Authentication failed. '
            'Your client certificate is not valid.'))
        return redirect_to_login(next_url)

    # SSL entries for this certificate?
    user = authenticate(ssl_info=ssl_info)

    # If the user is logged in, no need to create an account
    # If there is an SSL entries, no need for account creation,
    # just need to login, treated after
    if 'do_creation' in request.session and not user \
            and not request.user.is_authenticated():
        from backend import SSLBackend
        logger.info('Account creation treatment')
        if SSLBackend().create_user(ssl_info):
            user = authenticate(ssl_info=ssl_info)
            logger.info('account created for %s' % user.username)
        else:
            logger.error('account creation failure')
            messages.add_message(request, messages.ERROR,
            _('SSL Client Authentication failed. Internal server error.'))
            return HttpResponseRedirect(next_url)

    # No SSL entries and no user session, redirect account linking page
    if not user and not request.user.is_authenticated():
        return render_to_response('auth/account_linking_ssl.html',
                context_instance=RequestContext(request))

    # No SSL entries but active user session, perform account linking
    if not user and request.user.is_authenticated():
        from backend import SSLBackend
        if SSLBackend().link_user(ssl_info, request.user):
            logger.info('Successful linking of the SSL '
               'Certificate to an account, redirection to %s' % next_url)
        else:
            logger.error('login() failed')
            messages.add_message(request, messages.ERROR,
            _('SSL Client Authentication failed. Internal server error.'))
        return HttpResponseRedirect(next_url)

    # SSL Entries found for this certificate,
    # if the user is logged out, we login
    if not request.user.is_authenticated():
        login(request, user)
        models.AuthenticationEvent.objects.create(who=user.username,
                how='ssl', nonce=request.GET.get(NONCE_FIELD_NAME,''))
        logger.info('Successful SSL Client Authentication, '
            'redirection to %s' % next_url)
        return HttpResponseRedirect(next_url)

    # SSL Entries found for this certificate, if the user is logged in, we
    # check that the SSL entry for the certificate is this user.
    # else, we make this certificate point on that user.
    if user.username != request.user.username:
        logger.warning('[auth2_ssl]: The certificate belongs to %s, '
            'but %s is logged with, we change the association!'
            % (user.username, request.user.username))
        from backend import SSLBackend
        cert = SSLBackend().get_certificate(ssl_info)
        cert.user = request.user
        cert.save()

    logger.info('Successful SSL Client Authentication, '
        'redirection to %s' % next_url)
    return HttpResponseRedirect(next_url)

###
 # post_account_linking
 # @request
 #
 # Called after an account linking.
 ###
@csrf_exempt
def post_account_linking(request):
    logger.info('auth2_ssl Return after account linking form filled')
    if request.method == "POST":
        if 'do_creation' in request.POST \
                and request.POST['do_creation'] == 'on':
            logger.info('account creation asked')
            request.session['do_creation'] = 'do_creation'
            if 'next' in request.session:
                next_url = request.session['next']
            else:
                next_url = request.path
            qs = { REDIRECT_FIELD_NAME: next_url }
            url = '%s?%s' % (reverse('user_signin_ssl'), urllib.urlencode(qs))
            return HttpResponseRedirect(url)
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            logger.info('form valid')
            user = form.get_user()
            try:
                login(request, user)
                models.AuthenticationEvent.objects.create(who=user.username,
                how='password', nonce=request.GET.get(NONCE_FIELD_NAME,''))
            except:
                logger.error('login() failed')
                messages.add_message(request, messages.ERROR,
                _('SSL Client Authentication failed. Internal server error.'))

            logger.debug('session opened')
            return redirect('user_signin_ssl')
        else:
            logger.warning('form not valid - Try again! (Brute force?)')
            return render(request, 'auth/account_linking_ssl.html')
    else:
        return render(request, 'auth/account_linking_ssl.html')

def profile(request, template_name='ssl/profile.html'):
    certificates = models.ClientCertificate.objects.filter(user=request.user)
    ctx = { 'certificates': certificates }
    return render_to_string(template_name, RequestContext(request, ctx))

@prevent_access_to_transient_users
def delete_certificate(request, certificate_pk):
    qs = models.ClientCertificate.objects.filter(pk=certificate_pk)
    count = qs.count()
    qs.delete()
    if count:
        logger.info('client certificate %s deleted', certificate_pk)
        messages.info(request, _('Certificate deleted.'))
    return HttpResponseRedirect(reverse('account_management') + '#a2-ssl-certificate-profile')

class SslErrorView(TemplateView):
    template_name = 'error_ssl.html'
error_ssl = SslErrorView.as_view()

def register(request):
    '''Registration page for SSL auth without CA'''
    next_url = request.GET.get(REDIRECT_FIELD_NAME, settings.LOGIN_REDIRECT_URL)
    return registration.views.register(request, success_url=next_url,
            form_class=functools.partial(forms.RegistrationForm,
                request=request))

