import uuid
import logging

import requests

from django.core.urlresolvers import reverse
from django.utils.translation import get_language, ugettext as _
from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME, authenticate
from django.conf import settings
from django.views.generic.base import View
from django.http import HttpResponseBadRequest

from authentic2.decorators import setting_enabled
from authentic2.utils import redirect, login, good_next_url

from . import app_settings, models
from .utils import get_provider, get_provider_by_issuer


@setting_enabled('ENABLE', settings=app_settings)
def oidc_login(request, pk, next_url=None, *args, **kwargs):
    logger = logging.getLogger(__name__)
    provider = get_provider(pk)
    scopes = set(provider.scopes.split()) | set(['openid'])
    state = str(uuid.uuid4())
    nonce = request.GET.get('nonce') or str(uuid.uuid4())
    display = set()
    prompt = set()
    params = {
        'client_id': provider.client_id,
        'scope': ' '.join(scopes),
        'response_type': 'code',
        'redirect_uri': request.build_absolute_uri(reverse('oidc-login-callback')),
        'state': state,
        'nonce': nonce,
    }
    if 'login_hint' in request.GET:
        params['login_hint'] = request.GET['login_hint']
    if get_language():
        params['ui_locales'] = get_language()
    if provider.max_auth_age:
        params['max_age'] = provider.max_auth_age
    if display:
        params['display'] = ' '.join(display)
    if prompt:
        params['prompt'] = ' '.join(prompt)
    # FIXME: display ?
    # FIXME: prompt ? passive and force_authn
    # FIXME: login_hint ?
    # FIXME: id_token_hint ?
    # FIXME: acr_values ?
    # save request state
    saved_state = request.session.setdefault('auth_oidc', {}).setdefault(state, {})
    saved_state['request'] = params
    saved_state['issuer'] = provider.issuer
    next_url = next_url or request.GET.get(REDIRECT_FIELD_NAME, '')
    if good_next_url(request, next_url):
        saved_state['next_url'] = next_url
    request.session.modified = True  # necessary if auth_oidc already exists
    logger.debug('auth_oidc: sent request to authorization endpoint %r', params)
    return redirect(redirect, provider.authorization_endpoint, params=params, resolve=False)


@setting_enabled('ENABLE', settings=app_settings)
def login_initiate(request, *args, **kwargs):
    if 'iss' not in request.GET:
        return HttpResponseBadRequest('missing iss parameter')
    issuer = request.GET['iss']
    try:
        provider = get_provider_by_issuer(issuer)
    except models.OIDCProvider.DoesNotExist:
        return HttpResponseBadRequest(u'unknown issuer %s' % issuer)
    return login(request, pk=provider.pk, next_url=request.GET.get('target_link_uri'))


class LoginCallback(View):
    def continue_to_next_url(self):
        return redirect(self.request,
                        self.oidc_state.get('next_url', settings.LOGIN_REDIRECT_URL),
                        resolve=False)

    def get(self, request, *args, **kwargs):
        logger = logging.getLogger(__name__)
        code = request.GET.get('code')
        state = request.GET.get('state')
        oidc_state = self.oidc_state = request.session.get('auth_oidc', {}).get(state)
        if not state or not oidc_state or 'request' not in oidc_state:
            messages.warning(request, _('Login with OpenIDConnect failed, state lost.'))
            logger.warning('auth_oidc: state lost')
            return redirect(request, settings.LOGIN_REDIRECT_URL)
        try:
            issuer = oidc_state.get('issuer')
            provider = get_provider_by_issuer(issuer)
        except models.OIDCProvider.DoesNotExist:
            messages.warning(request, _('Unknown OpenID connect issuer'))
            logger.warning('auth_oidc: unknown issuer, %s', issuer)
            return self.continue_to_next_url()

        # FIXME is idp initiated SSO allowed ? in this case state is maybe not mandatory
        if 'error' in request.GET:  # error code path
            error_description = request.GET.get('error_description')
            error_url = request.GET.get('error_url')
            msg = u'auth_oidc: error received '
            if error_description:
                msg += u'%s (%s)' % (error_description, request.GET['error'])
            else:
                msg += request.GET['error']
            if error_url:
                msg += u' see %s' % error_url
            logger.warning(msg)
            if provider:
                messages.warning(request, _('Login with %(name)s failed, report %(request_id)s '
                                            'to an administrator.')
                                 % {
                                     'name': provider.name,
                                     'request_id': request.request_id,
                })
            else:
                messages.warning(request, _('Login with OpenIDConnect failed, report %s to an '
                                            'administrator') % request.request_id)
            return self.continue_to_next_url()
        if not code:
            messages.warning(request, _('Missing code, report %s to an administrator') %
                             request.request_id)
            logger.warning('auth_oidc: missing code, %r', request.GET)
            return self.continue_to_next_url()
        try:
            token_endpoint_request = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': request.build_absolute_uri(request.path),
            }
            logger.debug('auth_oidc: sent request to token endpoint %r', token_endpoint_request)
            response = requests.post(provider.token_endpoint, data=token_endpoint_request,
                                     auth=(provider.client_id, provider.client_secret), timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.warning(
                'auth_oidc: failed to contact the token_endpoint for %(issuer)s, %(exception)s' % {
                    'issuer': issuer,
                    'exception': e,
                })
            messages.warning(request, _('Provider %(name)s is down, report %(request_id)s to '
                                        'an administrator. ') %
                             {
                                 'name': provider.name,
                                 'request_id': request.request_id,
            })
            return self.continue_to_next_url()
        try:
            result = response.json()
        except ValueError as e:
            logger.warning(u'auth_oidc: response from %s is not a JSON document, %s, %r' %
                           (provider.token_endpoint, e, response.content))
            messages.warning(request, _('Provider %(name)s is down, report %(request_id)s to '
                                        'an administrator. ') %
                             {
                                 'name': provider.name,
                                 'request_id': request.request_id,
            })
            return self.continue_to_next_url()
        if ('access_token' not in result or 'token_type' not in result or
                result['token_type'] != 'Bearer' or 'id_token' not in result):
            logger.warning(u'auth_oidc: invalid token endpoint response from %s: %r' % (
                provider.token_endpoint, result))
            messages.warning(request, _('Provider %(name)s is down, report %(request_id)s to '
                                        'an administrator. ') %
                             {
                                 'name': provider.name,
                                 'request_id': request.request_id,
            })
            return self.continue_to_next_url()
        access_token = result.get('access_token')
        user = authenticate(access_token=access_token, id_token=result['id_token'])
        if user:
            login(request, user, 'oidc')
        else:
            messages.warning(request, _('No user found'))
        return self.continue_to_next_url()


login_callback = setting_enabled('ENABLE', settings=app_settings)(LoginCallback.as_view())


@setting_enabled('ENABLE', settings=app_settings)
def logout(request, *args, **kwargs):
    return
