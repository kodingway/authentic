import urlparse
import base64
import json
import datetime

import pytest

from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWKSet, JWK

import utils

from django.core.urlresolvers import reverse
from django.utils.timezone import now

from authentic2_idp_oidc.models import OIDCClient, OIDCAuthorization, OIDCCode, OIDCAccessToken
from authentic2_idp_oidc.utils import make_sub
from authentic2.a2_rbac.utils import get_default_ou
from authentic2.utils import make_url
from authentic2_auth_oidc.utils import parse_timestamp
from django_rbac.utils import get_role_model

JWKSET = {
    "keys": [
        {
            "qi": "h_zifVD-ChelxZUVxhICNcgGkQz26b-EdIlLY9rN7SX_aD3sLI_JHEHV4Bz3kV5eW8O4qJ8SHhfUdHGK-gRH7FVOGoXnXACf47QoXowHzsPLL64wCuZENTl7hIRGLY-BInULkfTQfuiVSMoxPjsVNTMBzMiz0bNjMQyMyvW5xH4",
            "kty": "RSA",
            "d": "pUcL4-LDBy3rqJWip269h5Hd6nLvqjXltfkVe_mL-LwZPHmCrUaj_SX54SnCY3Wyf7kxhoMYUac62lQ71923uJPFFdiavAujbNrtZPq32i4C-1apWXW8OGJr8VoVDqalxj9SAq1G54wbbsaAPrZdyuqy-esNxDqDigfbM-cWgngBBYo5CSsfnmnd05N2cUS26L7QzWbNHwilnBTE9e_J7rK3xUCDKrobv6_LiI-AhMmBHJSrCxjexh0wzfBi_Ntj9BGCcPThDjG8SQvaV-aLNdLfIy2XO3i076RLBB6Hm_yHuAparrwp-pPE48eQdiYjrSAFalz4ojWQ3_ByLA6uAQ",
            "q": "2FvfeWnIlWNUipan7DIBlJrmz5EinJNxrQ-BNwPHrAoIM8qvyC7jPy09YxZs5Y9CMMZSal6C4Nm2LHBFxHU9z1qd5XDzbk19G-y1lDqZizVXr876TpiAjuq03rcoMQm8dQru_pVjUdgxR64vKyJ9CaFMAqcpZeEMIqAvzhQG8uE",
            "dp": "Kg4HPGpzenhK2ser6nfM1Yt-pkqBbWQotvqsxGptECXpbN7vweupvL5kJPeRrbsXKp9QE7DXTN1sG9puJxMSwtgiv4hr9Va9e9WOC6PMd2VY7tgw5uKMpPLMc5y82PusRhBoRh0SUUsjyQxK9PGtWYnGZXbAoaIYPdMyDlosfqU",
            "dq": "QuUNEHYTjZTbo8n2-4FumarXKGBAalbwM8jyc7cYemnTpWfKt8M_gd4T99oMK2IC3h_DhZ3ZK3pE6DKCb76sMLtczH8C1RziTMsATWdc5_zDMtl07O4b-ZQ5_g51P8w515pc0JwRzFFi0z3Y2aZdMKgNX1id5SES5nXOshHhICE",
            "n": "0lN6CiJGFD8BSPV_azLoEl6Nq-WlHkU743D5rqvzw1sOaxstMGxAhVk2YIhWwfvapV6XjO_yvc4778VBTELOdjRw6BGUdBJepdwkL__TPyjEVhqMQj9MKhEU4GUy9w0Lsilb5D01kfrOKpmdcYw4jhcDvb0H4-LZgh1Vk84vF4WaQCUg_AX4drVDQOjoU8kuWIM8gz9w6zEsbIw-gtMRpFwS8ncA0zDX5VfyC77iMxzFftDIP2gM5GvdevMzvP9IRkRRBhP9vV4JchBFPHSA9OPJcnySjJJNW6aAJn6P6JasN1z68khjufM09J8UzmLAZYOq7gUG95Ox1KsV-g337Q",
            "e": "AQAB",
            "p": "-Nyj_Sw3f2HUqSssCZv84y7b3blOtGGAhfYN_JtGfcTQv2bOtxrIUzeonCi-Z_1W4hO10tqxJcOB0ibtDqkDlLhnLaIYOBfriITRFK83EJG5sC-0KTmFzUXFTA2aMc1QgP-Fu6gUfQpPqLgWxhx8EFhkBlBZshKU5-C-385Sco0"
        }
    ]
}


@pytest.fixture
def oidc_settings(settings):
    settings.A2_IDP_OIDC_JWKSET = JWKSET
    return settings


def test_get_jwkset(oidc_settings):
    from authentic2_idp_oidc.utils import get_jwkset
    get_jwkset()

OIDC_CLIENT_PARAMS = [
    {
        'authorization_flow': OIDCClient.FLOW_IMPLICIT,
    },
    {},
    {
        'identifier_policy': OIDCClient.POLICY_UUID,
    },
    {
        'identifier_policy': OIDCClient.POLICY_EMAIL,
        'post_logout_redirect_uris': '',
    },
    {
        'idtoken_algo': OIDCClient.ALGO_HMAC,
    },
]


@pytest.fixture(params=OIDC_CLIENT_PARAMS)
def oidc_client(request, superuser, app):
    url = reverse('admin:authentic2_idp_oidc_oidcclient_add')
    assert OIDCClient.objects.count() == 0
    response = utils.login(app, superuser, path=url)
    response.form.set('name', 'oidcclient')
    response.form.set('slug', 'oidcclient')
    response.form.set('ou', get_default_ou().pk)
    response.form.set('unauthorized_url', 'https://example.com/southpark/')
    response.form.set('redirect_uris', 'https://example.com/callback')
    response.form.set('post_logout_redirect_uris', 'https://example.com/')
    for key, value in request.param.iteritems():
        response.form.set(key, value)
    response = response.form.submit().follow()
    assert OIDCClient.objects.count() == 1
    client = OIDCClient.objects.get()
    utils.logout(app)
    return client


def client_authentication_headers(oidc_client):
    token = base64.b64encode('%s:%s' % (oidc_client.client_id, oidc_client.client_secret))
    return {'Authorization': 'Basic %s' % token}


def bearer_authentication_headers(access_token):
    return {'Authorization': 'Bearer %s' % str(access_token)}


@pytest.mark.parametrize('login_first', [(True,), (False,)])
def test_authorization_code_sso(login_first, oidc_settings, oidc_client, simple_user, app):
    redirect_uri = oidc_client.redirect_uris.split()[0]
    params = {
        'client_id': oidc_client.client_id,
        'scope': 'openid profile email',
        'redirect_uri': redirect_uri,
        'state': 'xxx',
        'nonce': 'yyy',
    }

    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        params['response_type'] = 'code'
    elif oidc_client.authorization_flow == oidc_client.FLOW_IMPLICIT:
        params['response_type'] = 'token id_token'
    authorize_url = make_url('oidc-authorize', params=params)

    if login_first:
        utils.login(app, simple_user)
    response = app.get(authorize_url)
    if not login_first:
        response = response.follow()
        assert response.request.path == reverse('auth_login')
        response.form.set('username', simple_user.username)
        response.form.set('password', simple_user.username)
        response = response.form.submit(name='login-password-submit')
        response = response.follow()
        assert response.request.path == reverse('oidc-authorize')
    assert 'a2-oidc-authorization-form' in response.content
    assert OIDCAuthorization.objects.count() == 0
    assert OIDCCode.objects.count() == 0
    assert OIDCAccessToken.objects.count() == 0
    response = response.form.submit('accept')
    assert OIDCAuthorization.objects.count() == 1
    authz = OIDCAuthorization.objects.get()
    assert authz.client == oidc_client
    assert authz.user == simple_user
    assert authz.scope_set() == set('openid profile email'.split())
    assert authz.expired >= now()
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        assert OIDCCode.objects.count() == 1
        code = OIDCCode.objects.get()
        assert code.client == oidc_client
        assert code.user == simple_user
        assert code.scope_set() == set('openid profile email'.split())
        assert code.state == 'xxx'
        assert code.nonce == 'yyy'
        assert code.redirect_uri == redirect_uri
        assert code.session_key == app.session.session_key
        assert code.auth_time <= now()
        assert code.expired >= now()
    assert response['Location'].startswith(redirect_uri)
    location = urlparse.urlparse(response['Location'])
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        query = urlparse.parse_qs(location.query)
        assert set(query.keys()) == set(['code', 'state'])
        assert query['code'] == [code.uuid]
        code = query['code'][0]
        assert query['state'] == ['xxx']

        token_url = make_url('oidc-token')
        response = app.post(token_url, params={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': oidc_client.redirect_uris.split()[0],
        }, headers=client_authentication_headers(oidc_client))
        assert 'error' not in response.json
        assert 'access_token' in response.json
        assert 'expires_in' in response.json
        assert 'id_token' in response.json
        assert response.json['token_type'] == 'Bearer'
        access_token = response.json['access_token']
        id_token = response.json['id_token']
    elif oidc_client.authorization_flow == oidc_client.FLOW_IMPLICIT:
        assert location.fragment
        query = urlparse.parse_qs(location.fragment)
        assert OIDCAccessToken.objects.count() == 1
        access_token = OIDCAccessToken.objects.get()
        assert set(query.keys()) == set(['access_token', 'token_type', 'expires_in', 'id_token',
                                         'state'])
        assert query['access_token'] == [access_token.uuid]
        assert query['token_type'] == ['Bearer']
        assert query['state'] == ['xxx']
        access_token = query['access_token'][0]
        id_token = query['id_token'][0]

    if oidc_client.idtoken_algo == oidc_client.ALGO_RSA:
        key = JWKSet.from_json(app.get(reverse('oidc-certs')).content)
    elif oidc_client.idtoken_algo == oidc_client.ALGO_HMAC:
        key = JWK(kty='oct', k=base64.b64encode(oidc_client.client_secret.encode('utf-8')))
    else:
        raise NotImplementedError
    jwt = JWT(jwt=id_token, key=key)
    claims = json.loads(jwt.claims)
    assert set(claims) >= set(['iss', 'sub', 'aud', 'exp', 'iat', 'nonce', 'auth_time', 'acr'])
    assert claims['nonce'] == 'yyy'
    assert response.request.url.startswith(claims['iss'])
    assert claims['aud'] == oidc_client.client_id
    assert parse_timestamp(claims['iat']) <= now()
    assert parse_timestamp(claims['auth_time']) <= now()
    assert parse_timestamp(claims['exp']) >= now()
    if login_first:
        assert claims['acr'] == 0
    else:
        assert claims['acr'] == 1

    user_info_url = make_url('oidc-user-info')
    response = app.get(user_info_url, headers=bearer_authentication_headers(access_token))
    assert response.json['sub'] == make_sub(oidc_client, simple_user)
    assert response.json['preferred_username'] == simple_user.username
    assert response.json['given_name'] == simple_user.first_name
    assert response.json['family_name'] == simple_user.last_name
    assert response.json['email'] == simple_user.email
    assert response.json['email_verified'] is True

    # Now logout
    params = {}
    if oidc_client.post_logout_redirect_uris:
        params = {
            'post_logout_redirect_uri': oidc_client.post_logout_redirect_uris,
        }
    logout_url = make_url('oidc-logout', params=params)
    response = app.get(logout_url)
    if oidc_client.post_logout_redirect_uris:
        assert 'You have been logged out' in response.content
        assert 'https://example.com' in response.content
        assert '_auth_user_id' not in app.session
    else:
        response = response.maybe_follow()
        assert 'You have been logged out' in response.content
        assert response.request.environ['HTTP_HOST'] == 'testserver'
        assert response.request.environ['PATH_INFO'] == '/login/'


def assert_oidc_error(response, error, error_description=None, fragment=False):
    location = urlparse.urlparse(response['Location'])
    query = location.fragment if fragment else location.query
    query = urlparse.parse_qs(query)
    assert query['error'] == [error]
    if error_description:
        assert len(query['error_description']) == 1
        assert error_description in query['error_description'][0]


def assert_authorization_response(response, fragment=False, **kwargs):
    location = urlparse.urlparse(response['Location'])
    query = location.fragment if fragment else location.query
    query = urlparse.parse_qs(query)
    for key, value in kwargs.iteritems():
        if value is None:
            assert key in query
        elif isinstance(value, list):
            assert query[key] == value
        else:
            assert value in query[key][0]


def test_invalid_request(oidc_settings, oidc_client, simple_user, app):
    redirect_uri = oidc_client.redirect_uris.split()[0]
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        fragment = False
        response_type = 'code'
    elif oidc_client.authorization_flow == oidc_client.FLOW_IMPLICIT:
        fragment = True
        response_type = 'id_token token'
    else:
        raise NotImplementedError

    # client_id
    authorize_url = make_url('oidc-authorize', params={})

    response = app.get(authorize_url, status=400)
    assert 'missing parameter \'client_id\'' in response.content

    # redirect_uri
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
    })

    response = app.get(authorize_url, status=400)
    assert 'missing parameter \'redirect_uri\'' in response.content

    # invalid client_id
    authorize_url = make_url('oidc-authorize', params={
        'client_id': 'xxx',
        'redirect_uri': redirect_uri,
    })

    response = app.get(authorize_url, status=400)
    assert 'unknown client_id' in response.content

    # missing response_type
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
    })

    response = app.get(authorize_url)
    assert_oidc_error(response, 'invalid_request', 'missing parameter \'response_type\'',
                      fragment=fragment)
    # missing scope
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
    })

    response = app.get(authorize_url)
    assert_oidc_error(response, 'invalid_request', 'missing parameter \'scope\'', fragment=fragment)

    # invalid max_age
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid',
        'max_age': 'xxx',
    })
    response = app.get(authorize_url)
    assert_oidc_error(response, 'invalid_request', 'max_age is not', fragment=fragment)
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid',
        'max_age': '-1',
    })
    response = app.get(authorize_url)
    assert_oidc_error(response, 'invalid_request', 'max_age is not', fragment=fragment)

    # invalid redirect_uri
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': 'xxx',
        'response_type': 'code',
        'scope': 'openid',
    })

    response = app.get(authorize_url)
    assert_oidc_error(response, 'invalid_request', 'unauthorized redirect_uri', fragment=fragment)

    # unsupported response_type
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'xxx',
        'scope': 'openid',
    })

    response = app.get(authorize_url)
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        assert_oidc_error(response, 'unsupported_response_type', 'only code is supported')
    elif oidc_client.authorization_flow == oidc_client.FLOW_IMPLICIT:
        assert_oidc_error(response, 'unsupported_response_type',
                          'only "id_token token" or "id_token" are supported', fragment=fragment)

    # openid scope is missing
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'profile',
    })

    response = app.get(authorize_url)
    assert_oidc_error(response, 'invalid_request', 'openid scope is missing', fragment=fragment)

    # use of an unknown scope
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile zob',
    })

    response = app.get(authorize_url)
    assert_oidc_error(response, 'invalid_scope', fragment=fragment)

    # cancel
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile',
        'cancel': '1',
    })

    response = app.get(authorize_url)
    assert_oidc_error(response, 'access_denied', error_description='user did not authenticate',
                      fragment=fragment)

    # prompt=none
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile',
        'prompt': 'none',
    })

    response = app.get(authorize_url)
    assert_oidc_error(response, 'login_required', error_description='prompt is none',
                      fragment=fragment)

    utils.login(app, simple_user)

    # prompt=none max_age=0
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile',
        'max_age': '0',
        'prompt': 'none',
    })

    response = app.get(authorize_url)
    assert_oidc_error(response, 'login_required', error_description='prompt is none',
                      fragment=fragment)

    # max_age=0
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile',
        'max_age': '0',
    })
    response = app.get(authorize_url)
    assert urlparse.urlparse(response['Location']).path == reverse('auth_login')

    # prompt=login
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile',
        'prompt': 'login',
    })
    response = app.get(authorize_url)
    assert urlparse.urlparse(response['Location']).path == reverse('auth_login')

    # user refuse authorization
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile',
        'prompt': 'none',
    })
    response = app.get(authorize_url)
    assert_oidc_error(response, 'consent_required', error_description='prompt is none',
                      fragment=fragment)

    # user refuse authorization
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile',
    })
    response = app.get(authorize_url)
    response = response.form.submit('refuse')
    assert_oidc_error(response, 'access_denied', error_description='user denied access',
                      fragment=fragment)

    # authorization exists
    authorize = OIDCAuthorization.objects.create(
        client=oidc_client, user=simple_user, scopes='openid profile email',
        expired=now() + datetime.timedelta(days=2))
    response = app.get(authorize_url)
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        assert_authorization_response(response, code=None, fragment=fragment)
    elif oidc_client.authorization_flow == oidc_client.FLOW_IMPLICIT:
        assert_authorization_response(response, access_token=None, id_token=None, expires_in=None,
                                      token_type=None, fragment=fragment)

    # client ask for explicit authorization
    authorize_url = make_url('oidc-authorize', params={
        'client_id': oidc_client.client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': 'openid email profile',
        'prompt': 'consent',
    })
    response = app.get(authorize_url)
    assert 'a2-oidc-authorization-form' in response.content
    # check all authorization have been deleted, it's our policy
    assert OIDCAuthorization.objects.count() == 0

    # authorization has expired
    OIDCCode.objects.all().delete()
    authorize.expired = now() - datetime.timedelta(days=2)
    authorize.save()
    response = app.get(authorize_url)
    assert 'a2-oidc-authorization-form' in response.content
    authorize.expired = now() + datetime.timedelta(days=2)
    authorize.scopes = 'openid profile'
    authorize.save()
    assert OIDCAuthorization.objects.count() == 1
    response = response.form.submit('accept')
    assert OIDCAuthorization.objects.count() == 1
    # old authorizations have been deleted
    assert OIDCAuthorization.objects.get().pk != authorize.pk

    # check expired codes
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        assert OIDCCode.objects.count() == 1
        code = OIDCCode.objects.get()
        assert code.is_valid()
        # make code expire
        code.expired = now() - datetime.timedelta(seconds=120)
        assert not code.is_valid()
        code.save()
        location = urlparse.urlparse(response['Location'])
        query = urlparse.parse_qs(location.query)
        assert set(query.keys()) == set(['code'])
        assert query['code'] == [code.uuid]
        code = query['code'][0]
        token_url = make_url('oidc-token')
        response = app.post(token_url, params={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': oidc_client.redirect_uris.split()[0],
        }, headers=client_authentication_headers(oidc_client), status=400)
        assert 'error' in response.json
        assert response.json['error'] == 'invalid_request'
        assert response.json['desc'] == 'code has expired or user is disconnected'

    # invalid logout
    logout_url = make_url('oidc-logout', params={
        'post_logout_redirect_uri': 'https://whatever.com/',
    })
    response = app.get(logout_url)
    assert '_auth_user_id' in app.session
    assert 'Location' in response.headers

    # check code expiration after logout
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        code = OIDCCode.objects.get()
        code.expired = now() + datetime.timedelta(seconds=120)
        code.save()
        assert code.is_valid()
        utils.logout(app)
        code = OIDCCode.objects.get()
        assert not code.is_valid()
        response = app.post(token_url, params={
            'grant_type': 'authorization_code',
            'code': code.uuid,
            'redirect_uri': oidc_client.redirect_uris.split()[0],
        }, headers=client_authentication_headers(oidc_client), status=400)
        assert 'error' in response.json
        assert response.json['error'] == 'invalid_request'
        assert response.json['desc'] == 'code has expired or user is disconnected'


def test_expired_manager(db, simple_user):
    expired = now() - datetime.timedelta(seconds=1)
    not_expired = now() + datetime.timedelta(days=1)
    client = OIDCClient.objects.create(
        name='client',
        slug='client',
        ou=get_default_ou(),
        redirect_uris='https://example.com/')
    OIDCAuthorization.objects.create(
        client=client,
        user=simple_user,
        scopes='openid',
        expired=expired)
    OIDCAuthorization.objects.create(
        client=client,
        user=simple_user,
        scopes='openid',
        expired=not_expired)
    assert OIDCAuthorization.objects.count() == 2
    OIDCAuthorization.objects.cleanup()
    assert OIDCAuthorization.objects.count() == 1

    OIDCCode.objects.create(
        client=client,
        user=simple_user,
        scopes='openid',
        redirect_uri='https://example.com/',
        session_key='xxx',
        auth_time=now(),
        expired=expired)
    OIDCCode.objects.create(
        client=client,
        user=simple_user,
        scopes='openid',
        redirect_uri='https://example.com/',
        session_key='xxx',
        auth_time=now(),
        expired=not_expired)
    assert OIDCCode.objects.count() == 2
    OIDCCode.objects.cleanup()
    assert OIDCCode.objects.count() == 1

    OIDCAccessToken.objects.create(
        client=client,
        user=simple_user,
        scopes='openid',
        session_key='xxx',
        expired=expired)
    OIDCAccessToken.objects.create(
        client=client,
        user=simple_user,
        scopes='openid',
        session_key='xxx',
        expired=not_expired)
    assert OIDCAccessToken.objects.count() == 2
    OIDCAccessToken.objects.cleanup()
    assert OIDCAccessToken.objects.count() == 1


@pytest.fixture
def simple_oidc_client(db):
    return OIDCClient.objects.create(
        name='client',
        slug='client',
        ou=get_default_ou(),
        redirect_uris='https://example.com/')


def test_client_secret_post_authentication(oidc_settings, app, simple_oidc_client, simple_user):
    utils.login(app, simple_user)
    redirect_uri = simple_oidc_client.redirect_uris.split()[0]

    params = {
        'client_id': simple_oidc_client.client_id,
        'scope': 'openid profile email',
        'redirect_uri': redirect_uri,
        'state': 'xxx',
        'nonce': 'yyy',
        'response_type': 'code',
    }

    authorize_url = make_url('oidc-authorize', params=params)
    response = app.get(authorize_url)
    response = response.form.submit('accept')
    location = urlparse.urlparse(response['Location'])
    query = urlparse.parse_qs(location.query)
    code = query['code'][0]
    token_url = make_url('oidc-token')
    response = app.post(token_url, params={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': simple_oidc_client.client_id,
        'client_secret': simple_oidc_client.client_secret,
    })

    assert 'error' not in response.json
    assert 'access_token' in response.json
    assert 'expires_in' in response.json
    assert 'id_token' in response.json
    assert response.json['token_type'] == 'Bearer'


@pytest.mark.parametrize('login_first', [(True,), (False,)])
def test_role_control_access(login_first, oidc_settings, oidc_client, simple_user, app):
    # authorized_role
    role_authorized = get_role_model().objects.create(
        name='Goth Kids', slug='goth-kids', ou=get_default_ou())
    oidc_client.add_authorized_role(role_authorized)

    redirect_uri = oidc_client.redirect_uris.split()[0]
    params = {
        'client_id': oidc_client.client_id,
        'scope': 'openid profile email',
        'redirect_uri': redirect_uri,
        'state': 'xxx',
        'nonce': 'yyy',
    }

    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        params['response_type'] = 'code'
    elif oidc_client.authorization_flow == oidc_client.FLOW_IMPLICIT:
        params['response_type'] = 'token id_token'
    authorize_url = make_url('oidc-authorize', params=params)

    if login_first:
        utils.login(app, simple_user)

    # user not authorized
    response = app.get(authorize_url)
    assert 'https://example.com/southpark/' in response.content

    # user authorized
    simple_user.roles.add(role_authorized)
    simple_user.save()
    response = app.get(authorize_url)

    if not login_first:
        response = response.follow()
        response.form.set('username', simple_user.username)
        response.form.set('password', simple_user.username)
        response = response.form.submit(name='login-password-submit')
        response = response.follow()
    response = response.form.submit('accept')
    authz = OIDCAuthorization.objects.get()
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        code = OIDCCode.objects.get()
    location = urlparse.urlparse(response['Location'])
    if oidc_client.authorization_flow == oidc_client.FLOW_AUTHORIZATION_CODE:
        query = urlparse.parse_qs(location.query)
        code = query['code'][0]
        token_url = make_url('oidc-token')
        response = app.post(token_url, params={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': oidc_client.redirect_uris.split()[0],
        }, headers=client_authentication_headers(oidc_client))
        id_token = response.json['id_token']
    elif oidc_client.authorization_flow == oidc_client.FLOW_IMPLICIT:
        query = urlparse.parse_qs(location.fragment)
        id_token = query['id_token'][0]

    if oidc_client.idtoken_algo == oidc_client.ALGO_RSA:
        key = JWKSet.from_json(app.get(reverse('oidc-certs')).content)
    elif oidc_client.idtoken_algo == oidc_client.ALGO_HMAC:
        key = JWK(kty='oct', k=base64.b64encode(oidc_client.client_secret.encode('utf-8')))
    else:
        raise NotImplementedError
    jwt = JWT(jwt=id_token, key=key)
    claims = json.loads(jwt.claims)
    if login_first:
        assert claims['acr'] == 0
    else:
        assert claims['acr'] == 1
