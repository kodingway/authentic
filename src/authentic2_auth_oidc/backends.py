import logging
import datetime

import requests

from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK

from django.utils.timezone import now
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from authentic2.crypto import base64url_encode

from . import models, utils


class OIDCBackend(ModelBackend):
    def authenticate(self, access_token=None, id_token=None, **kwargs):
        logger = logging.getLogger(__name__)
        if id_token is None:
            return
        original_id_token = id_token
        try:
            id_token = utils.IDToken(id_token)
        except ValueError as e:
            logger.warning(u'auth_oidc: invalid id_token %r: %s', id_token, e)
            return None

        try:
            provider = utils.get_provider_by_issuer(id_token.iss)
        except models.OIDCProvider.DoesNotExist:
            logger.warning('auth_oidc: unknown issuer %r in authenticate')
            return None

        if provider.idtoken_algo == models.OIDCProvider.ALGO_RSA:
            key = provider.jwkset
            if not key:
                logger.warning('auth_oidc: idtoken signature algorithm is RSA but '
                               'no JWKSet is defined on provider %s', id_token.iss)
                return None
            if len(key['keys']) == 1:
                key = list(key['keys'])[0]
            algs = ['RS256', 'RS384', 'RS512']
        elif provider.idtoken_algo == models.OIDCProvider.ALGO_HMAC:
            key = JWK(kty='oct', k=base64url_encode(provider.client_secret.encode('utf-8')))
            if not provider.client_secret:
                logger.warning('auth_oidc: idtoken signature algorithm is HMAC but '
                               'no client_secret is defined on provider %s', id_token.iss)
                return None
            algs = ['HS256', 'HS384', 'HS512']
        else:
            key = None

        if key:
            jwt = JWT(jwt=original_id_token,
                      key=key,
                      check_claims={}, algs=algs)
            jwt.claims

        if isinstance(id_token.aud, unicode) and provider.client_id != id_token.aud:
            logger.warning(u'auth_oidc: invalid id_token audience %s != provider client_id %s',
                           id_token.aud, provider.client_id)
            return None
        if isinstance(id_token.aud, list):
            if provider.client_id not in id_token.aud:
                logger.warning(u'auth_oidc: invalid id_token audience %s != provider client_id %s',
                               id_token.aud, provider.client_id)
                return None
            if len(id_token.aud) > 1 and 'azp' not in id_token:
                logger.warning(u'auth_oidc: multiple audience and azp not set',
                               id_token.aud, provider.client_id)
                return None
            if id_token.azp != provider.client_id:
                logger.warning(u'auth_oidc: multiple audience and azp %r does not match client_id'
                               ' %r',
                               id_token.azp, provider.client_id)
                return None

        if id_token.exp < now():
            logger.warning(u'auth_oidc: id_token expired %s', id_token.exp)
            return None

        if provider.max_auth_age:
            if not id_token.iat:
                logger.warning('auth_oidc: provider configured for fresh authentication but iat is '
                               'missing from idtoken')
                return None
            duration = now() - id_token.iat
            if duration > datetime.timedelta(seconds=provider.max_auth_age):
                logger.warning('auth_oidc: authentication is too old %s (%s old)', id_token.iat,
                               duration)
                return None

        User = get_user_model()
        user = None
        try:
            user = User.objects.get(oidc_account__provider=provider,
                                    oidc_account__sub=id_token.sub,
                                    is_active=True)
        except User.DoesNotExist:
            pass
        need_user_info = False
        for claim_mapping in provider.claim_mappings.all():
            need_user_info = need_user_info or not claim_mapping.idtoken_claim

        user_info = None
        if need_user_info:
            if not access_token:
                logger.warning('auth_oidc: need user info for some claims, but no access token was '
                               'returned')
                return None
            try:
                response = requests.get(provider.userinfo_endpoint,
                                        headers={
                                            'Authorization': 'Bearer %s' % access_token,
                                        })
                response.raise_for_status()
            except requests.RequestException as e:
                logger.warning(u'auth_oidc: failed to retrieve user info %s', e)
            else:
                try:
                    user_info = response.json()
                except ValueError as e:
                    logger.warngin(u'auth_oidc: bad JSON in user info response, %s (%r)', e,
                                   response.content)

        # check for required claims
        for claim_mapping in provider.claim_mappings.all():
            claim = claim_mapping.claim
            if claim_mapping.required:
                if claim_mapping.idtoken_claim and claim not in id_token:
                    logger.warning(u'auth_oidc: cannot create user missing required claim %r in '
                                   u'id_token (%r)',
                                   claim, id_token)
                    return None
                elif not user_info or claim not in user_info:
                    logger.warning(u'auth_oidc: cannot create user missing required claim %r in '
                                   u'user_info (%r)', claim, user_info)
                    return None

        created = False
        if not user:
            if provider.strategy == models.OIDCProvider.STRATEGY_CREATE:
                user = User.objects.create(ou=provider.ou)
                models.OIDCAccount.objects.create(
                    provider=provider,
                    user=user,
                    sub=id_token.sub)
                created = True
            else:
                logger.warning(u'auth_oidc: cannot create user for sub %r as issuer %r does not'
                               u' allow it', id_token.sub, id_token.iss)
                return None

        # map claims to attributes or user fields
        attributes = utils.get_attributes()
        attributes_map = {attribute.name: attribute for attribute in attributes}
        save_user = False
        mappings = []
        for claim_mapping in provider.claim_mappings.all():
            claim = claim_mapping.claim
            if claim_mapping.idtoken_claim:
                source = id_token
            else:
                source = user_info
            if claim not in source:
                continue
            value = source.get(claim)
            attribute = claim_mapping.attribute
            if claim_mapping.verified == models.OIDCClaimMapping.VERIFIED_CLAIM:
                verified = bool(source.get(claim + '_verified', False))
            elif claim_mapping.verified == models.OIDCClaimMapping.ALWAYS_VERIFIED:
                verified = True
            else:
                verified = False
            mappings.append((attribute, value, verified))

        # legacy attributes
        for attribute, value, verified in mappings:
            if attribute in ('username', 'first_name', 'last_name', 'email'):
                setattr(user, attribute, value)
                save_user = True
	if user.ou != provider.ou:
            user.ou = provider.ou
            save_user = True
        if save_user:
            user.save()

        # new style attributes
        for attribute, value, verified in mappings:
            if attribute in attributes_map:
                attributes_map[attribute].set_value(user, value, verified=verified)

        if created:
            logger.info(u'auth_oidc: created user %s for sub %s and issuer %s',
                        user, id_token.sub, id_token.iss)
        return user

    def get_saml2_authn_context(self):
        import lasso
        return lasso.SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
