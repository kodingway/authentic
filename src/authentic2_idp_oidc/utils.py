import json
import hashlib
import urlparse
import base64

from jwcrypto.jwk import JWK, JWKSet, InvalidJWKValue
from jwcrypto.jwt import JWT

from django.core.exceptions import ImproperlyConfigured
from django.conf import settings

from authentic2 import hooks

from . import app_settings


def base64url(content):
    return base64.urlsafe_b64encode(content).strip('=')


def get_jwkset():
    try:
        jwkset = json.dumps(app_settings.JWKSET)
    except Exception as e:
        raise ImproperlyConfigured('invalid setting A2_IDP_OIDC_JWKSET: %s' % e)
    try:
        jwkset = JWKSet.from_json(jwkset)
    except InvalidJWKValue as e:
        raise ImproperlyConfigured('invalid setting A2_IDP_OIDC_JWKSET: %s' % e)
    if len(jwkset['keys']) < 1:
        raise ImproperlyConfigured('empty A2_IDP_OIDC_JWKSET')
    return jwkset


def get_first_rsa_sig_key():
    for key in get_jwkset()['keys']:
        if key._params['kty'] != 'RSA':
            continue
        use = key._params.get('use')
        if use is None or use == 'sig':
            return key
    return None


def make_idtoken(client, claims):
    '''Make a serialized JWT targeted for this client'''
    if client.idtoken_algo == client.ALGO_HMAC:
        header = {'alg': 'HS256'}
        jwk = JWK(kty='oct', k=base64url(client.client_secret.encode('utf-8')))
    elif client.idtoken_algo == client.ALGO_RSA:
        header = {'alg': 'RS256'}
        jwk = get_first_rsa_sig_key()
        header['kid'] = jwk.key_id
        if jwk is None:
            raise ImproperlyConfigured('no RSA key for signature operation in A2_IDP_OIDC_JWKSET')
    else:
        raise NotImplementedError
    jwt = JWT(header=header, claims=claims)
    jwt.make_signed_token(jwk)
    return jwt.serialize()


def scope_set(data):
    '''Convert a scope string into a set of scopes'''
    return set([scope.strip() for scope in data.split()])


def clean_words(data):
    '''Clean and order a list of words'''
    return u' '.join(sorted(map(unicode.strip, data.split())))


def url_domain(url):
    return urlparse.urlparse(url).netloc.split(':')[0]


def make_sub(client, user):
    if client.identifier_policy == client.POLICY_PAIRWISE:
        return make_pairwise_sub(client, user)
    elif client.identifier_policy == client.POLICY_UUID:
        return unicode(user.uuid)
    elif client.identifier_policy == client.POLICY_EMAIL:
        return user.email
    else:
        raise NotImplementedError


def make_pairwise_sub(client, user):
    '''Make a pairwise sub'''
    sector_identifier = None
    if client.sector_identifier_uri:
        sector_identifier = url_domain(client.sector_identifier_uri)
    else:
        for redirect_uri in client.redirect_uris.split():
            hostname = urlparse.urlparse(redirect_uri).netloc.split(':')[0]
            if sector_identifier is None:
                sector_identifier = hostname
            elif sector_identifier != hostname:
                raise ImproperlyConfigured('all redirect_uri do not have the same hostname')
    sub = sector_identifier + str(user.uuid) + settings.SECRET_KEY
    sub = base64.b64encode(hashlib.sha256(sub).digest())
    return sub


def create_user_info(client, user, scope_set, id_token=False):
    '''Create user info dictionnary'''
    user_info = {
        'sub': make_sub(client, user)
    }
    if 'profile' in scope_set:
        user_info['family_name'] = user.last_name
        user_info['given_name'] = user.first_name
        if user.username:
            user_info['preferred_username'] = user.username.split('@', 1)[0]
    if 'email' in scope_set:
        user_info['email'] = user.email
        user_info['email_verified'] = True
    hooks.call_hooks('idp_oidc_modify_user_info', client, user, scope_set, user_info)
    return user_info
