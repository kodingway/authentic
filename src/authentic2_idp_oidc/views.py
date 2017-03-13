import logging
import datetime
import json
import base64
import time

from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseNotAllowed
from django.utils.timezone import now, UTC
from django.utils.http import urlencode
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib import messages
from django.conf import settings
from django.utils.translation import ugettext as _

from authentic2.decorators import setting_enabled
from authentic2.utils import (login_require, redirect, timestamp_from_datetime,
                              last_authentication_event)
from authentic2.views import logout as a2_logout

from . import app_settings, models, utils


@setting_enabled('ENABLE', settings=app_settings)
def openid_configuration(request, *args, **kwargs):
    metadata = {
        'issuer': request.build_absolute_uri('/'),
        'authorization_endpoint': request.build_absolute_uri(reverse('oidc-authorize')),
        'token_endpoint': request.build_absolute_uri(reverse('oidc-token')),
        'jwks_uri': request.build_absolute_uri(reverse('oidc-certs')),
        'end_session_endpoint': request.build_absolute_uri(reverse('oidc-logout')),
        'response_types_supported': ['code'],
        'subject_types_supported': ['public', 'pairwise'],
        'token_endpoint_auth_methods_supported': [
            'clien_secret_post', 'client_secret_basic',
        ],
        'id_token_signing_alg_values_supported': [
            'RS256', 'HS256',
        ],
        'userinfo_endpoint': request.build_absolute_uri(reverse('oidc-user-info')),
    }
    return HttpResponse(json.dumps(metadata), content_type='application/json')


@setting_enabled('ENABLE', settings=app_settings)
def certs(request, *args, **kwargs):
    return HttpResponse(utils.get_jwkset().export(private_keys=False),
                        content_type='application/json')


def authorization_error(request, redirect_uri, error, error_description=None, error_uri=None,
                        state=None, fragment=False):
    params = {
        'error': error,
    }
    if error_description:
        params['error_description'] = error_description
    if error_uri:
        params['error_uri'] = error_uri
    if state is not None:
        params['state'] = state
    if fragment:
        return redirect(request, redirect_uri + '#%s' % urlencode(params), resolve=False)
    else:
        return redirect(request, redirect_uri, params=params, resolve=False)


@setting_enabled('ENABLE', settings=app_settings)
def authorize(request, *args, **kwargs):
    logger = logging.getLogger(__name__)
    start = now()

    try:
        client_id = request.GET['client_id']
        redirect_uri = request.GET['redirect_uri']
    except KeyError as k:
        return HttpResponseBadRequest('invalid request: missing parameter %s' % k.args[0])
    try:
        client = models.OIDCClient.objects.get(client_id=client_id)
    except models.OIDCClient.DoesNotExist:
        return HttpResponseBadRequest('invalid request: unknown client_id')
    fragment = client.authorization_flow == client.FLOW_IMPLICIT

    state = request.GET.get('state')

    try:
        response_type = request.GET['response_type']
        scope = request.GET['scope']
    except KeyError as k:
        return authorization_error(request, redirect_uri, 'invalid_request',
                                   state=state,
                                   error_description='missing parameter %s' % k.args[0],
                                   fragment=fragment)

    prompt = set(filter(None, request.GET.get('prompt', '').split()))
    nonce = request.GET.get('nonce')
    scopes = utils.scope_set(scope)

    max_age = request.GET.get('max_age')
    if max_age:
        try:
            max_age = int(max_age)
            if max_age < 0:
                raise ValueError
        except ValueError:
            return authorization_error(request, redirect_uri, 'invalid_request',
                                       error_description='max_age is not a positive integer',
                                       state=state,
                                       fragment=fragment)

    if redirect_uri not in client.redirect_uris.split():
        return authorization_error(request, redirect_uri, 'invalid_request',
                                   error_description='unauthorized redirect_uri',
                                   state=state,
                                   fragment=fragment)
    if client.authorization_flow == client.FLOW_AUTHORIZATION_CODE:
        if response_type != 'code':
            return authorization_error(request, redirect_uri, 'unsupported_response_type',
                                       error_description='only code is supported',
                                       state=state,
                                       fragment=fragment)
    elif client.authorization_flow == client.FLOW_IMPLICIT:
        if not set(filter(None, response_type.split())) in (set(['id_token', 'token']),
                                                            set(['id_token'])):
            return authorization_error(request, redirect_uri, 'unsupported_response_type',
                                       error_description='only "id_token token" or "id_token" '
                                       'are supported',
                                       state=state,
                                       fragment=fragment)
    else:
        raise NotImplementedError
    if 'openid' not in scopes:
        return authorization_error(request, redirect_uri, 'invalid_request',
                                   error_description='openid scope is missing',
                                   state=state,
                                   fragment=fragment)
    allowed_scopes = app_settings.SCOPES or ['openid', 'email', 'profile']
    if not (scopes <= set(allowed_scopes)):
        message = 'only "%s" scope(s) are supported, but "%s" requested' % (
            ', '.join(allowed_scopes), ', '.join(scopes))
        return authorization_error(request, redirect_uri, 'invalid_scope',
                                   error_description=message,
                                   state=state,
                                   fragment=fragment)

    # authentication canceled by user
    if 'cancel' in request.GET:
        logger.info(u'authentication canceled for service %s', client.name)
        return authorization_error(request, redirect_uri, 'access_denied',
                                   error_description='user did not authenticate',
                                   state=state,
                                   fragment=fragment)

    if not request.user.is_authenticated() or 'login' in prompt:
        if 'none' in prompt:
            return authorization_error(request, redirect_uri, 'login_required',
                                       error_description='login is required but prompt is none',
                                       state=state,
                                       fragment=fragment)
        params = {}
        if nonce is not None:
            params['nonce'] = nonce
        return login_require(request, params=params)

    # if user not authorized, a ServiceAccessDenied exception
    # is raised and handled by ServiceAccessMiddleware
    client.authorize(request.user)

    last_auth = last_authentication_event(request.session)
    if max_age is not None and time.time() - last_auth['when'] >= max_age:
        if 'none' in prompt:
            return authorization_error(request, redirect_uri, 'login_required',
                                       error_description='login is required but prompt is none',
                                       state=state,
                                       fragment=fragment)
        params = {}
        if nonce is not None:
            params['nonce'] = nonce
        return login_require(request, params=params)

    qs = models.OIDCAuthorization.objects.filter(client=client, user=request.user)
    if 'consent' in prompt:
        # if consent is asked we delete existing authorizations
        # it seems to be the safer option
        qs.delete()
        qs = models.OIDCAuthorization.objects.none()
    else:
        qs = qs.filter(expired__gte=start)
    authorized_scopes = set()
    for authorization in qs:
        authorized_scopes |= authorization.scope_set()
    if (authorized_scopes & scopes) < scopes:
        if 'none' in prompt:
            return authorization_error(request, redirect_uri, 'consent_required',
                                       error_description='consent is required but prompt is none',
                                       state=state,
                                       fragment=fragment)
        if request.method == 'POST':
            if 'accept' in request.POST:
                pk_to_deletes = []
                for authorization in qs:
                    # clean obsolete authorizations
                    if authorization.scope_set() <= scopes:
                        pk_to_deletes.append(authorization.pk)
                models.OIDCAuthorization.objects.create(
                    client=client, user=request.user, scopes=u' '.join(sorted(scopes)),
                    expired=start + datetime.timedelta(days=365))
                if pk_to_deletes:
                    models.OIDCAuthorization.objects.filter(pk__in=pk_to_deletes).delete()
                logger.info(u'authorized scopes %s for service %s', ' '.join(scopes),
                            client.name)
            else:
                logger.info(u'refused scopes %s for service %s', ' '.join(scopes),
                            client.name)
                return authorization_error(request, redirect_uri, 'access_denied',
                                           error_description='user denied access',
                                           state=state,
                                           fragment=fragment)
        else:
            return render(request, 'authentic2_idp_oidc/authorization.html',
                          {
                              'client': client,
                              'scopes': scopes - set(['openid']),
                          })
    if response_type == 'code':
        code = models.OIDCCode.objects.create(
            client=client, user=request.user, scopes=u' '.join(scopes),
            state=state, nonce=nonce, redirect_uri=redirect_uri,
            expired=start + datetime.timedelta(seconds=30),
            auth_time=datetime.datetime.fromtimestamp(last_auth['when'], UTC()),
            session_key=request.session.session_key)
        logger.info(u'sending code %s for scopes %s for service %s',
                    code.uuid, ' '.join(scopes),
                    client.name)
        params = {
            'code': unicode(code.uuid),
        }
        if state is not None:
            params['state'] = state
        return redirect(request, redirect_uri, params=params, resolve=False)
    else:
        # FIXME: we should probably factorize this part with the token endpoint similar code
        need_access_token = 'token' in response_type.split()
        expires_in = 3600 * 8
        if need_access_token:
            access_token = models.OIDCAccessToken.objects.create(
                client=client,
                user=request.user,
                scopes=u' '.join(scopes),
                session_key=request.session.session_key,
                expired=start + datetime.timedelta(seconds=expires_in))
        acr = 0
        if nonce is not None and last_auth.get('nonce') == nonce:
            acr = 1
        id_token = utils.create_user_info(client, request.user, scopes, id_token=True)
        id_token.update({
            'iss': request.build_absolute_uri('/'),
            'sub': utils.make_sub(client, request.user),
            'aud': client.client_id,
            'exp': timestamp_from_datetime(
                start + datetime.timedelta(seconds=30)),
            'iat': timestamp_from_datetime(start),
            'auth_time': last_auth['when'],
            'acr': acr,
        })
        if nonce is not None:
            id_token['nonce'] = nonce
        params = {
            'id_token': utils.make_idtoken(client, id_token),
        }
        if state is not None:
            params['state'] = state
        if need_access_token:
            params.update({
                'access_token': access_token.uuid,
                'token_type': 'Bearer',
                'expires_in': expires_in,
            })
        # query is transfered through the hashtag
        return redirect(request, redirect_uri + '#%s' % urlencode(params), resolve=False)


def authenticate_client(request, client=None):
    '''Authenticate client on the token endpoint'''

    if 'HTTP_AUTHORIZATION' in request.META:
        authorization = request.META['HTTP_AUTHORIZATION'].split()
        if authorization[0] != 'Basic' or len(authorization) != 2:
            return None
        try:
            decoded = base64.b64decode(authorization[1])
        except TypeError:
            return None
        parts = decoded.split(':')
        if len(parts) != 2:
            return None
        client_id, client_secret = parts
    elif 'client_id' in request.POST:
        client_id = request.POST['client_id']
        client_secret = request.POST.get('client_secret', '')
    else:
        return None
    if not client:
        try:
            client = models.OIDCClient.objects.get(client_id=client_id)
        except models.OIDCClient.DoesNotExist:
            return None
    if client.client_secret != client_secret:
        return None
    return client


def invalid_request(desc=None):
    content = {
        'error': 'invalid_request',
    }
    if desc:
        content['desc'] = desc
    return HttpResponseBadRequest(json.dumps(content), content_type='application/json')


@setting_enabled('ENABLE', settings=app_settings)
@csrf_exempt
def token(request, *args, **kwargs):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    grant_type = request.POST.get('grant_type')
    if grant_type != 'authorization_code':
        return invalid_request('grant_type is not authorization_code')
    code = request.POST.get('code')
    if code is None:
        return invalid_request('missing code')
    try:
        oidc_code = models.OIDCCode.objects.select_related().get(uuid=code)
    except models.OIDCCode.DoesNotExist:
        return invalid_request('invalid code')
    if not oidc_code.is_valid():
        return invalid_request('code has expired or user is disconnected')
    client = authenticate_client(request, client=oidc_code.client)
    if client is None:
        return HttpResponse('unauthenticated', status=401)
    # delete immediately
    models.OIDCCode.objects.filter(uuid=code).delete()
    redirect_uri = request.POST.get('redirect_uri')
    if oidc_code.redirect_uri != redirect_uri:
        return invalid_request('invalid redirect_uri')
    expires_in = 3600 * 8
    access_token = models.OIDCAccessToken.objects.create(
        client=client,
        user=oidc_code.user,
        scopes=oidc_code.scopes,
        session_key=oidc_code.session_key,
        expired=oidc_code.created + datetime.timedelta(seconds=expires_in))
    start = now()
    acr = 0
    if (oidc_code.nonce is not None and last_authentication_event(oidc_code.session).get('nonce') ==
            oidc_code.nonce):
        acr = 1
    # prefill id_token with user info
    id_token = utils.create_user_info(client, oidc_code.user, oidc_code.scope_set(), id_token=True)
    id_token.update({
        'iss': request.build_absolute_uri('/'),
        'sub': utils.make_sub(client, oidc_code.user),
        'aud': client.client_id,
        'exp': timestamp_from_datetime(
            start + datetime.timedelta(seconds=30)),
        'iat': timestamp_from_datetime(start),
        'auth_time': timestamp_from_datetime(oidc_code.auth_time),
        'acr': acr,
    })
    if oidc_code.nonce is not None:
        id_token['nonce'] = oidc_code.nonce
    response = HttpResponse(json.dumps({
        'access_token': unicode(access_token.uuid),
        'token_type': 'Bearer',
        'expires_in': expires_in,
        'id_token': utils.make_idtoken(client, id_token),
    }), content_type='application/json')
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response


def authenticate_access_token(request):
    if 'HTTP_AUTHORIZATION' not in request.META:
        return None
    authorization = request.META['HTTP_AUTHORIZATION'].split()
    if authorization[0] != 'Bearer' or len(authorization) != 2:
        return None
    try:
        access_token = models.OIDCAccessToken.objects.select_related().get(uuid=authorization[1])
    except models.OIDCAccessToken.DoesNotExist:
        return None
    if not access_token.is_valid():
        return None
    return access_token


@setting_enabled('ENABLE', settings=app_settings)
@csrf_exempt
def user_info(request, *args, **kwargs):
    access_token = authenticate_access_token(request)
    if access_token is None:
        return HttpResponse('unauthenticated', status=401)
    user_info = utils.create_user_info(access_token.client, access_token.user,
                                       access_token.scope_set())
    return HttpResponse(json.dumps(user_info), content_type='application/json')


@setting_enabled('ENABLE', settings=app_settings)
def logout(request):
    params = {}
    post_logout_redirect_uri = request.GET.get('post_logout_redirect_uri')
    if post_logout_redirect_uri:
        providers = models.OIDCClient.objects.filter(
            post_logout_redirect_uris__contains=post_logout_redirect_uri)
        for provider in providers:
            if post_logout_redirect_uri in provider.post_logout_redirect_uris.split():
                break
        else:
            messages.warning(request, _('Invalid post logout URI'))
            return redirect(request, settings.LOGIN_REDIRECT_URL)
        params[REDIRECT_FIELD_NAME] = post_logout_redirect_uri
    # FIXME: do something with id_token_hint
    id_token_hint = request.GET.get('id_token_hint')
    return a2_logout(request, next_url=post_logout_redirect_uri, do_local=False,
                     check_referer=False)
