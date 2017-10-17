# -*- coding: utf-8 -*-
import datetime
import pytest
import urlparse
import json

from jwcrypto.jwk import JWKSet, JWK
from jwcrypto.jwt import JWT

from httmock import urlmatch, HTTMock

from django.utils.timezone import UTC
from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from django.utils.timezone import now

from authentic2_auth_oidc.utils import base64url_decode, parse_id_token, IDToken
from authentic2_auth_oidc.models import OIDCProvider, OIDCClaimMapping
from authentic2_auth_oidc.auth_frontends import get_providers
from authentic2.models import AttributeValue
from authentic2.utils import timestamp_from_datetime
from authentic2.a2_rbac.utils import get_default_ou
from authentic2.crypto import base64url_encode

import utils


def test_base64url_decode():
    with pytest.raises(TypeError):
        base64url_decode('x')
    base64url_decode('aa')

header = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ'
payload = ('ewogImlzcyI6ICJodHRw'
           'Oi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiw'
           'KICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIi'
           'wKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAKfQ')
signature = ('ggW8hZ'
             '1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP9'
             '9Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccM'
             'g4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKP'
             'XfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvR'
             'YLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0'
             'nx7RkKU8NXNHq-rvKMzqg')
payload_decoded = {
    'sub': '248289761001',
    'iss': 'http://server.example.com',
    'aud': 's6BhdRkqt3',
    'nonce': 'n-0S6_WzA2Mj',
    'iat': 1311280970,
    'exp': 1311281970,
}


def test_parse_id_token():
    # example taken from https://tools.ietf.org/html/rfc7519#section-3.1
    assert parse_id_token('%s.%s.%s' % (header, payload, signature)) == payload_decoded
    with pytest.raises(ValueError):
        parse_id_token('x%s.%s.%s' % (header, payload, signature))
    with pytest.raises(ValueError):
        parse_id_token('%s.%s.%s' % ('$', payload, signature))
    with pytest.raises(ValueError):
        parse_id_token('%s.x%s.%s' % (header, payload, signature))
    with pytest.raises(ValueError):
        parse_id_token('%s.%s.%s' % (header, '$', signature))
    # signagure is currently ignored
    assert parse_id_token('%s.%s.x%s' % (header, payload, signature)) == payload_decoded
    assert parse_id_token('%s.%s.%s' % (header, payload, '-')) == payload_decoded


def test_idtoken():
    token = IDToken('%s.%s.%s' % (header, payload, signature))
    assert token.sub == payload_decoded['sub']
    assert token.iss == payload_decoded['iss']
    assert token.aud == payload_decoded['aud']
    assert token.nonce == payload_decoded['nonce']
    assert token.iat == datetime.datetime(2011, 7, 21, 20, 42, 50, tzinfo=UTC())
    assert token.exp == datetime.datetime(2011, 7, 21, 20, 59, 30, tzinfo=UTC())


@pytest.fixture
def oidc_provider_jwkset():
    key = JWK.generate(kty='RSA', size=512)
    jwkset = JWKSet()
    jwkset.add(key)
    return jwkset


@pytest.fixture(params=[OIDCProvider.ALGO_RSA, OIDCProvider.ALGO_HMAC])
def oidc_provider(request, db, oidc_provider_jwkset):
    idtoken_algo = request.param
    from authentic2_auth_oidc.utils import get_provider, get_provider_by_issuer
    get_provider.cache.clear()
    get_provider_by_issuer.cache.clear()
    if idtoken_algo == OIDCProvider.ALGO_RSA:
        jwkset = json.loads(oidc_provider_jwkset.export())
    else:
        jwkset = None
    provider = OIDCProvider.objects.create(
        id=1,
        ou=get_default_ou(),
        name='OIDIDP',
        issuer='https://idp.example.com/',
        authorization_endpoint='https://idp.example.com/authorize',
        token_endpoint='https://idp.example.com/token',
        end_session_endpoint='https://idp.example.com/logout',
        userinfo_endpoint='https://idp.example.com/user_info',
        token_revocation_endpoint='https://idp.example.com/revoke',
        max_auth_age=10,
        strategy=OIDCProvider.STRATEGY_CREATE,
        jwkset_json=jwkset,
        idtoken_algo=idtoken_algo,
    )
    provider.full_clean()
    OIDCClaimMapping.objects.create(
        provider=provider,
        claim='sub',
        attribute='username',
        idtoken_claim=True)
    OIDCClaimMapping.objects.create(
        provider=provider,
        claim='email',
        attribute='email')
    OIDCClaimMapping.objects.create(
        provider=provider,
        claim='email',
        required=True,
        attribute='email')
    OIDCClaimMapping.objects.create(
        provider=provider,
        claim='given_name',
        required=True,
        verified=OIDCClaimMapping.ALWAYS_VERIFIED,
        attribute='first_name')
    OIDCClaimMapping.objects.create(
        provider=provider,
        claim='family_name',
        required=True,
        verified=OIDCClaimMapping.VERIFIED_CLAIM,
        attribute='last_name')
    return provider


@pytest.fixture
def code():
    return 'xxxx'


def oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code, extra_id_token=None,
                       extra_user_info=None, sub='john.doe'):
    token_endpoint = urlparse.urlparse(oidc_provider.token_endpoint)
    userinfo_endpoint = urlparse.urlparse(oidc_provider.userinfo_endpoint)
    token_revocation_endpoint = urlparse.urlparse(oidc_provider.token_revocation_endpoint)

    @urlmatch(netloc=token_endpoint.netloc, path=token_endpoint.path)
    def token_endpoint_mock(url, request):
        if urlparse.parse_qs(request.body).get('code') == [code]:
            id_token = {
                'iss': oidc_provider.issuer,
                'sub': sub,
                'iat': timestamp_from_datetime(now()),
                'aud': str(oidc_provider.client_id),
                'exp': timestamp_from_datetime(now() + datetime.timedelta(seconds=10)),
            }
            if extra_id_token:
                id_token.update(extra_id_token)

            if oidc_provider.idtoken_algo == OIDCProvider.ALGO_RSA:
                jwt = JWT(header={'alg': 'RS256'},
                          claims=id_token)
                jwt.make_signed_token(list(oidc_provider_jwkset['keys'])[0])
            else:
                jwt = JWT(header={'alg': 'HS256'},
                          claims=id_token)
                jwt.make_signed_token(
                    JWK(kty='oct',
                        k=base64url_encode(oidc_provider.client_secret.encode('utf-8'))))

            content = {
                'access_token': '1234',
                'token_type': 'Bearer',
                'id_token': jwt.serialize(),
            }
            return {
                'content': json.dumps(content),
                'headers': {
                    'content-type': 'application/json',
                },
            }
        else:
            return {
                'content': json.dumps({'error': 'invalid request'}),
                'headers': {
                    'content-type': 'application/json',
                },
                'status': 400,
            }

    @urlmatch(netloc=userinfo_endpoint.netloc, path=userinfo_endpoint.path)
    def user_info_endpoint_mock(url, request):
        user_info = {
            'sub': sub,
            'iss': oidc_provider.issuer,
            'given_name': 'John',
            'family_name': 'Doe',
            'email': 'john.doe@example.com',
        }
        if extra_user_info:
            user_info.update(extra_user_info)
        return {
            'content': json.dumps(user_info),
            'headers': {
                'content-type': 'application/json',
            },
        }

    @urlmatch(netloc=token_revocation_endpoint.netloc, path=token_revocation_endpoint.path)
    def token_revocation_endpoint_mock(url, request):
        query = urlparse.parse_qs(request.body)
        assert 'token' in query
        return {}
    return HTTMock(token_endpoint_mock, user_info_endpoint_mock, token_revocation_endpoint_mock)


@pytest.fixture
def login_url(oidc_provider):
    return reverse('oidc-login', kwargs={'pk': oidc_provider.pk})


@pytest.fixture
def login_callback_url(oidc_provider):
    return reverse('oidc-login-callback')


def check_simple_qs(qs):
    for k in qs:
        assert len(qs[k]) == 1
        qs[k] = qs[k][0]
    return qs


def test_sso(app, caplog, code, oidc_provider, oidc_provider_jwkset, login_url, login_callback_url):
    response = app.get('/admin/').maybe_follow()
    assert oidc_provider.name in response.content
    response = response.click(oidc_provider.name)
    location = urlparse.urlparse(response.location)
    endpoint = urlparse.urlparse(oidc_provider.authorization_endpoint)
    assert location.scheme == endpoint.scheme
    assert location.netloc == endpoint.netloc
    assert location.path == endpoint.path
    query = check_simple_qs(urlparse.parse_qs(location.query))
    assert query['state'] in app.session['auth_oidc']
    assert query['response_type'] == 'code'
    assert query['client_id'] == str(oidc_provider.client_id)
    assert query['scope'] == 'openid'
    assert query['redirect_uri'] == 'http://testserver' + reverse('oidc-login-callback')

    User = get_user_model()
    assert User.objects.count() == 0

    with utils.check_log(caplog, 'invalid token endpoint response'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code):
            response = app.get(login_callback_url, params={'code': 'yyyy', 'state': query['state']})
    with utils.check_log(caplog, 'invalid id_token %r'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code,
                                extra_id_token={'iss': None}):
            response = app.get(login_callback_url, params={'code': code, 'state': query['state']})
    with utils.check_log(caplog, 'invalid id_token %r'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code,
                                extra_id_token={'sub': None}):
            response = app.get(login_callback_url, params={'code': code, 'state': query['state']})
    with utils.check_log(caplog, 'authentication is too old'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code,
                                extra_id_token={'iat': 1}):
            response = app.get(login_callback_url, params={'code': code, 'state': query['state']})
    with utils.check_log(caplog, 'id_token expired'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code,
                                extra_id_token={'exp': 1}):
            response = app.get(login_callback_url, params={'code': code, 'state': query['state']})
    with utils.check_log(caplog, 'invalid id_token audience'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code,
                                extra_id_token={'aud': 'zz'}):
            response = app.get(login_callback_url, params={'code': code, 'state': query['state']})
    with utils.check_log(caplog, 'created user'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code):
            response = app.get(login_callback_url, params={'code': code, 'state': query['state']})
    assert urlparse.urlparse(response['Location']).path == '/admin/'
    assert User.objects.count() == 1
    user = User.objects.get()
    assert user.username == 'john.doe'
    assert user.first_name == 'John'
    assert user.last_name == 'Doe'
    assert user.email == 'john.doe@example.com'
    assert user.attributes.first_name == 'John'
    assert user.attributes.last_name == 'Doe'
    assert AttributeValue.objects.filter(content='John', verified=True).count() == 1
    assert AttributeValue.objects.filter(content='Doe', verified=False).count() == 1

    with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code,
                            extra_user_info={'family_name_verified': True}):
        response = app.get(login_callback_url, params={'code': code, 'state': query['state']})
    assert AttributeValue.objects.filter(content='Doe', verified=False).count() == 0
    assert AttributeValue.objects.filter(content='Doe', verified=True).count() == 1

    response = app.get(reverse('account_management'))
    with utils.check_log(caplog, 'revoked token from OIDC'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code):
            response = response.click(href='logout')
    assert 'https://idp.example.com/logout' in response.content


def test_show_on_login_page(app, oidc_provider):
    # we have a 5 seconds cache on list of providers, we have to work around it
    get_providers.cache.clear()
    response = app.get('/login/')
    assert 'oidc-a-oididp' in response.content

    # do not show this provider on login page anymore
    oidc_provider.show = False
    oidc_provider.save()

    # we have a 5 seconds cache on list of providers, we have to work around it
    get_providers.cache.clear()
    response = app.get('/login/')
    assert 'oidc-a-oididp' not in response.content


def test_strategy_find_uuid(app, caplog, code, oidc_provider, oidc_provider_jwkset, login_url,
                            login_callback_url, simple_user):

    get_providers.cache.clear()
    # no mapping please
    OIDCClaimMapping.objects.all().delete()
    oidc_provider.strategy = oidc_provider.STRATEGY_FIND_UUID
    oidc_provider.save()

    User = get_user_model()
    assert User.objects.count() == 1

    response = app.get('/').maybe_follow()
    assert oidc_provider.name in response.content
    response = response.click(oidc_provider.name)
    location = urlparse.urlparse(response.location)
    query = check_simple_qs(urlparse.parse_qs(location.query))

    # sub=john.doe, MUST not work
    with utils.check_log(caplog, 'cannot create user'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code):
            response = app.get(login_callback_url, params={'code': code, 'state': query['state']})

    # sub=simple_user.uuid MUST work
    with utils.check_log(caplog, 'found user using UUID'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code, sub=simple_user.uuid):
            response = app.get(login_callback_url, params={'code': code, 'state': query['state']})

    assert urlparse.urlparse(response['Location']).path == '/'
    assert User.objects.count() == 1
    user = User.objects.get()
    # verify user was not modified
    assert user.username == 'user'
    assert user.first_name == u'Jôhn'
    assert user.last_name == u'Dôe'
    assert user.email == 'user@example.net'
    assert user.attributes.first_name == u'Jôhn'
    assert user.attributes.last_name == u'Dôe'

    response = app.get(reverse('account_management'))
    with utils.check_log(caplog, 'revoked token from OIDC'):
        with oidc_provider_mock(oidc_provider, oidc_provider_jwkset, code):
            response = response.click(href='logout')
    assert 'https://idp.example.com/logout' in response.content
