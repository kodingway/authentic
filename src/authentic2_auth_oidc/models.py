import uuid
import json

from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from django.core.exceptions import ValidationError

from jsonfield import JSONField

from jwcrypto.jwk import JWKSet, InvalidJWKValue

from django_rbac.utils import get_ou_model_name

from . import managers


def validate_jwkset(data):
    data = json.dumps(data)
    try:
        JWKSet.from_json(data)
    except InvalidJWKValue as e:
        raise ValidationError(_('Invalid JWKSet: %s') % e)


class OIDCProvider(models.Model):
    STRATEGY_CREATE = 'create'
    STRATEGY_NONE = 'none'

    STRATEGIES = [
        (STRATEGY_CREATE, _('create')),
        (STRATEGY_NONE, _('none')),
    ]
    ALGO_NONE = 0
    ALGO_RSA = 1
    ALGO_HMAC = 2
    ALGO_CHOICES = [
        (ALGO_NONE, _('none')),
        (ALGO_RSA, _('RSA')),
        (ALGO_HMAC, _('HMAC')),
    ]

    name = models.CharField(
        unique=True,
        max_length=128,
        verbose_name=_('name'))
    issuer = models.CharField(
        max_length=256,
        verbose_name=_('issuer'),
        unique=True,
        db_index=True)
    client_id = models.CharField(
        max_length=128,
        default=uuid.uuid4,
        verbose_name=_('client id'))
    client_secret = models.CharField(
        max_length=128,
        default=uuid.uuid4,
        verbose_name=_('client secret'))
    # endpoints
    authorization_endpoint = models.URLField(
        max_length=128,
        verbose_name=_('authorization endpoint'))
    token_endpoint = models.URLField(
        max_length=128,
        verbose_name=_('token endpoint'))
    userinfo_endpoint = models.URLField(
        max_length=128,
        verbose_name=_('userinfo endpoint'))
    end_session_endpoint = models.URLField(
        max_length=128,
        blank=True,
        null=True,
        verbose_name=_('end session endpoint'))
    token_revocation_endpoint = models.URLField(
        max_length=128,
        blank=True,
        null=True,
        verbose_name=_('token revocation endpoint'))
    scopes = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('scopes'))
    jwkset_json = JSONField(
        verbose_name=_('JSON WebKey set'),
        null=True,
        blank=True,
        validators=[validate_jwkset])
    idtoken_algo = models.PositiveIntegerField(
        default=ALGO_RSA,
        choices=ALGO_CHOICES,
        verbose_name=_('IDToken signature algorithm'))

    # ou where new users should be created
    strategy = models.CharField(
        max_length=32,
        choices=STRATEGIES,
        verbose_name=_('strategy'))
    ou = models.ForeignKey(
        to=get_ou_model_name(),
        verbose_name=_('organizational unit'))

    # policy
    max_auth_age = models.PositiveIntegerField(
        verbose_name=_('max authentication age'),
        blank=True,
        null=True)

    # metadata
    created = models.DateTimeField(
        verbose_name=_('created'),
        auto_now_add=True)
    modified = models.DateTimeField(
        verbose_name=_('modified'),
        auto_now=True)

    objects = managers.OIDCProviderManager()

    @property
    def jwkset(self):
        if self.jwkset_json:
            return JWKSet.from_json(json.dumps(self.jwkset_json))
        return None

    def __unicode__(self):
        return self.name

    def __repr__(self):
        return '<OIDCProvider %r>' % self.issuer


class OIDCClaimMapping(models.Model):
    NOT_VERIFIED = 0
    VERIFIED_CLAIM = 1
    ALWAYS_VERIFIED = 2
    VERIFIED_CHOICES = [
        (NOT_VERIFIED, _('not verified')),
        (VERIFIED_CLAIM, _('verified claim')),
        (ALWAYS_VERIFIED, _('always verified')),
    ]

    provider = models.ForeignKey(
        to='OIDCProvider',
        verbose_name=_('provider'),
        related_name='claim_mappings')
    claim = models.CharField(
        max_length=64,
        verbose_name=_('claim'))
    attribute = models.CharField(
        max_length=64,
        verbose_name=_('attribute'))
    verified = models.PositiveIntegerField(
        default=NOT_VERIFIED,
        choices=VERIFIED_CHOICES,
        verbose_name=_('verified'))
    required = models.BooleanField(
        blank=True,
        default=False,
        verbose_name=_('required'))
    idtoken_claim = models.BooleanField(
        verbose_name=_('idtoken claim'),
        default=False,
        blank=True)
    created = models.DateTimeField(
        verbose_name=_('created'),
        auto_now_add=True)
    modified = models.DateTimeField(
        verbose_name=_('modified'),
        auto_now=True)

    objects = managers.OIDCClaimMappingManager()

    def natural_key(self):
        return (self.claim, self.attribute, self.verified, self.required)

    def __unicode__(self):
        s = u'{0} -> {1}'.format(self.claim, self.attribute)
        if self.verified:
            s += u', verified'
        if self.required:
            s += u', required'
        if self.idtoken_claim:
            s += u', idtoken'
        return s

    def __repr__(self):
        return '<OIDCClaimMapping %r:%r on provider %r verified:%s required:%s >' % (
            self.claim, self.attribute, self.provider and self.provider.issuer,
            self.verified, self.required)


class OIDCAccount(models.Model):
    created = models.DateTimeField(
        verbose_name=_('created'),
        auto_now_add=True)
    modified = models.DateTimeField(
        verbose_name=_('modified'),
        auto_now=True)
    provider = models.ForeignKey(
        to='OIDCProvider',
        verbose_name=_('provider'),
        related_name='accounts')
    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL,
        verbose_name=_('user'),
        related_name='oidc_account')
    sub = models.CharField(
        verbose_name=_('sub'),
        max_length=256,
        unique=True)

    def __unicode__(self):
        return u'{0} on {1} linked to {2}'.format(self.sub, self.provider and self.provider.issuer,
                                                  self.user)

    def __repr__(self):
        return '<OIDCAccount %r on %r>' % (self.sub, self.provider and self.provider.issuer)
