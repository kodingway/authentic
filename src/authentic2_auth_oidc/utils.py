import urlparse
import datetime
import base64
import json

import requests

from django.utils.timezone import UTC, make_aware
from django.shortcuts import get_object_or_404
from django.utils.translation import ugettext as _

from authentic2.decorators import GlobalCache
from authentic2.models import Attribute

TIMEOUT = 1


@GlobalCache(timeout=TIMEOUT)
def get_attributes():
    return Attribute.objects.all()


@GlobalCache(timeout=TIMEOUT)
def get_provider(pk):
    from . import models
    return get_object_or_404(models.OIDCProvider, pk=pk)


@GlobalCache(timeout=TIMEOUT)
def has_providers():
    from . import models
    return models.OIDCProvider.objects.all().exists()


@GlobalCache(timeout=TIMEOUT)
def get_provider_by_issuer(issuer):
    from . import models
    return models.OIDCProvider.objects.prefetch_related('claim_mappings').get(issuer=issuer)


def base64url_decode(input):
    rem = len(input) % 4
    if rem > 0:
        input += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(input)


def parse_id_token(id_token):
    try:
        id_token = str(id_token)
    except UnicodeDecodeError as e:
        raise ValueError('invalid characters in id_token')
    payload = id_token.split('.')
    if len(payload) == 5:
        raise ValueError('encrypted IDToken is unsupported')
    if len(payload) != 3:
        raise ValueError('IDToken does not have three parts, %d found' % len(payload))
    try:
        headers = base64url_decode(payload[0])
    except TypeError as e:
        raise ValueError('header is not base64 decodable: %s' % e)
    try:
        headers = json.loads(headers)
    except ValueError as e:
        raise ValueError('cannot JSON decode headers')
    if not isinstance(headers, dict):
        raise ValueError('JOSE header is not a dict %r' % headers)
    if 'typ' in headers and headers.get('typ') != 'JWT':
        raise ValueError('JOSE type is not JWT: %s' % headers)
    print 'headers', headers
    try:
        payload = base64url_decode(payload[1])
    except TypeError as e:
        raise ValueError('payload is not base64 decodable: %s' % e)
    try:
        payload = json.loads(payload)
    except ValueError as e:
        raise ValueError('invalid JSON payload: %s' % e)
    if not isinstance(payload, dict):
        raise ValueError('JOSE payload is not a dict %r' % payload)
    # FIXME : really check signature !!!
    if 'alg' not in headers or headers['alg'] is None or headers['alg'] == 'none':
        raise ValueError('unsigned token: %s' % headers)
    return payload


REQUIRED_ID_TOKEN_KEYS = set(['iss', 'sub', 'aud', 'exp', 'iat'])
KEY_TYPES = {
    'iss': unicode,
    'sub': unicode,
    'exp': int,
    'iat': int,
    'auth_time': int,
    'nonce': unicode,
    'acr': unicode,
    'azp': unicode,
    # aud and amr havec specific checks
}


def parse_timestamp(tstamp):
    if not isinstance(tstamp, int):
        raise ValueError('%s' % tstamp)
    tstamp = datetime.datetime.fromtimestamp(tstamp)
    return make_aware(tstamp, timezone=UTC())


class IDToken(str):
    auth_time = None
    nonce = None

    def __new__(cls, encoded):
        return str.__new__(cls, encoded)

    def __init__(self, encoded):
        decoded = parse_id_token(encoded)
        if not decoded:
            raise ValueError('invalid id_token')
        keys = set(decoded.keys())
        # check fields are ok
        if keys < REQUIRED_ID_TOKEN_KEYS:
            raise ValueError('missing field: %s' % (REQUIRED_ID_TOKEN_KEYS - keys))
        for key in keys:
            if key == 'aud':
                if not isinstance(decoded['aud'], (unicode, list)):
                    raise ValueError('invalid aud value: %r' % decoded['aud'])
                if isinstance(decoded['aud'], list) and not all(isinstance(v, unicode) for v in
                                                                decoded['aud']):
                    raise ValueError('invalid aud value: %r' % decoded['aud'])
            elif key == 'amr':
                if not isinstance(decoded['amr'], list):
                    raise ValueError('invalid amr value: %s' % decoded['amr'])
                if not all(isinstance(v, unicode) for v in decoded['amr']):
                    raise ValueError('invalid amr value: %s' % decoded['amr'])
            elif key in KEY_TYPES:
                if not isinstance(decoded[key], KEY_TYPES[key]):
                    raise ValueError('invalid %s value: %s' % (key, decoded[key]))
        self.iss = decoded.pop('iss')
        self.sub = decoded.pop('sub')
        self.aud = decoded.pop('aud')
        try:
            self.exp = parse_timestamp(decoded.pop('exp'))
        except ValueError as e:
            raise ValueError('invalid exp value: %s' % e)
        try:
            self.iat = parse_timestamp(decoded.pop('iat'))
        except ValueError as e:
            raise ValueError('invalid iat value: %s' % e)
        if 'auth_time' in decoded:
            try:
                self.auth_time = parse_timestamp(decoded.pop('auth_time'))
            except ValueError as e:
                raise ValueError('invalid auth_time value: %s' % e)
        self.nonce = decoded.pop('nonce', None)
        self.acr = decoded.pop('acr', None)
        self.azp = decoded.pop('azp', None)
        self.extra = decoded

    def __contains__(self, key):
        if key in self.__dict__:
            return True
        if key in self.extra:
            return True
        return False

    def __getitem__(self, key):
        if key in self.__dict__:
            return self.__dict__[key]
        if key in self.extra:
            return self.extra[key]
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

OPENID_CONFIGURATION_REQUIRED = set(
    ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'response_types_supported',
     'subject_types_supported', 'id_token_signing_alg_values_supported', 'userinfo_endpoint']
)


def check_https(url):
    return urlparse.urlparse(url).scheme == 'https'


def register_issuer(name, issuer=None, openid_configuration=None, verify=True, timeout=None):
    from . import models

    if issuer and not openid_configuration:
        openid_configuration_url = get_openid_configuration_url(issuer)
        try:
            response = requests.get(openid_configuration_url, verify=verify, timeout=timeout)
            response.raise_for_status()
        except requests.RequestException as e:
            raise ValueError(_('Unable to reach the OpenID Connect configuration for %(issuer)s: '
                               '%(error)s') % {
                                   'issuer': issuer,
                                   'error': e,
            })

    try:
        openid_configuration = openid_configuration or response.json()
        if not isinstance(openid_configuration, dict):
            raise ValueError(_('MUST be a dictionnary'))
        keys = set(openid_configuration.keys())
        if not keys >= OPENID_CONFIGURATION_REQUIRED:
            raise ValueError(_('missing keys %s') % (OPENID_CONFIGURATION_REQUIRED - keys))
        for key in ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri',
                    'userinfo_endpoint']:
            if not check_https(openid_configuration[key]):
                raise ValueError(_('%(key)s is not an https:// URL; %(value)s') % {
                    'key': key,
                    'value': openid_configuration[key],
                })
    except ValueError as e:
        raise ValueError(_('Invalid OpenID Connect configuration for %(issuer)s: '
                           '%(error)s') % (issuer, e))
    if 'code' not in openid_configuration['response_types_supported']:
        raise ValueError(_('auhtorization code flow is unsupported: code response type is '
                           'unsupported'))
    try:
        response = requests.get(openid_configuration['jwks_uri'], verify=verify, timeout=None)
        response.raise_for_status()
    except requests.RequestException as e:
            raise ValueError(_('Unable to reach the OpenID Connect JWKSet for %(issuer)s: '
                               '%(url)s %(error)s') % {
                                   'issuer': issuer,
                                   'url': openid_configuration['jwks_uri'],
                                   'error': e,
            })
    try:
        jwkset_json = response.json()
    except ValueError as e:
        raise ValueError(_('Invalid JSKSet document: %s') % e)
    try:
        old_pk = models.OIDCProvider.objects.get(issuer=openid_configuration['issuer']).pk
    except models.OIDCProvider.DoesNotExist:
        old_pk = None
    if (set(['RS256', 'RS384', 'RS512']) &
            set(openid_configuration['id_token_signing_alg_values_supported'])):
        idtoken_algo = models.OIDCProvider.ALGO_RSA
    elif (set(['HS256', 'HS384', 'HS512']) &
          set(openid_configuration['id_token_signing_alg_values_supported'])):
        idtoken_algo = models.OIDCProvider.HMAC
    else:
        raise ValueError(_('no common algorithm found for signing idtokens: %s') %
                         openid_configuration['id_token_signing_alg_values_supported'])
    kwargs = dict(
        name=name,
        issuer=openid_configuration['issuer'],
        authorization_endpoint=openid_configuration['authorization_endpoint'],
        token_endpoint=openid_configuration['token_endpoint'],
        userinfo_endpoint=openid_configuration['userinfo_endpoint'],
        jwkset_json=jwkset_json,
        idtoken_algo=idtoken_algo,
        strategy=models.OIDCProvider.STRATEGY_CREATE)
    if old_pk:
        models.OIDCProvider.objects.filter(pk=old_pk).update(**kwargs)
        return models.OIDCProvider.objects.get(pk=old_pk)
    else:
        return models.OIDCProvider.objects.create(**kwargs)


def get_openid_configuration_url(issuer):
    parsed = urlparse.urlparse(issuer)
    if parsed.query or parsed.fragment or parsed.scheme != 'https':
        raise ValueError(_('invalid issuer URL, it must use the https:// scheme and not have a '
                           'query or fragment'))
    issuer = urlparse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip('/'), None,
                                  None, None))
    return issuer + '/.well-known/openid-configuration'


