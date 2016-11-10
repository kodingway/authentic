import uuid
from importlib import import_module

from django.db import models
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from django.utils.timezone import now

from authentic2.models import Service

from . import utils, managers


def generate_uuid():
    return unicode(uuid.uuid4())


def validate_https_url(data):
    errors = []
    for url in data.split():
        try:
            URLValidator(schemes=['http', 'https'])(url)
        except ValidationError as e:
            errors.append(e)
    if errors:
        raise ValidationError(errors)


def strip_words(data):
    return u' '.join([url for url in data.split()])


class OIDCClient(Service):
    POLICY_UUID = 1
    POLICY_PAIRWISE = 2
    POLICY_EMAIL = 3

    IDENTIFIER_POLICIES = [
        (POLICY_UUID, _('uuid')),
        (POLICY_PAIRWISE, _('pairwise')),
        (POLICY_EMAIL, _('email')),
    ]

    ALGO_RSA = 1
    ALGO_HMAC = 2
    ALGO_CHOICES = [
        (ALGO_RSA, _('RSA')),
        (ALGO_HMAC, _('HMAC')),
    ]
    FLOW_AUTHORIZATION_CODE = 1
    FLOW_IMPLICIT = 2
    FLOW_CHOICES = [
        (FLOW_AUTHORIZATION_CODE, _('authorization code')),
        (FLOW_IMPLICIT, _('implicit/native')),
    ]

    client_id = models.CharField(
        max_length=255,
        verbose_name=_('client id'),
        unique=True,
        default=generate_uuid)
    client_secret = models.CharField(
        max_length=255,
        verbose_name=_('client secret'),
        default=generate_uuid)
    authorization_flow = models.PositiveIntegerField(
        verbose_name=_('authorization flow'),
        default=FLOW_AUTHORIZATION_CODE,
        choices=FLOW_CHOICES)
    redirect_uris = models.TextField(
        verbose_name=_('redirect URIs'),
        validators=[validate_https_url])
    sector_identifier_uri = models.URLField(
        verbose_name=_('sector identifier URI'),
        blank=True)
    identifier_policy = models.PositiveIntegerField(
        verbose_name=_('identifier policy'),
        default=POLICY_PAIRWISE,
        choices=IDENTIFIER_POLICIES)
    idtoken_algo = models.PositiveIntegerField(
        default=ALGO_RSA,
        choices=ALGO_CHOICES,
        verbose_name=_('IDToken signature algorithm'))

    # metadata
    created = models.DateTimeField(
        verbose_name=_('created'),
        auto_now_add=True)
    modified = models.DateTimeField(
        verbose_name=_('modified'),
        auto_now=True)

    def clean(self):
        self.redirect_uris = strip_words(self.redirect_uris)

    def __repr__(self):
        return ('<OIDCClient name:%r client_id:%s identifier_policy:%s>' %
                (self.name, self.client_id, self.get_identifier_policy_display()))


class OIDCAuthorization(models.Model):
    client = models.ForeignKey(
        to=OIDCClient,
        verbose_name=_('client'))
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        verbose_name=_('user'))
    scopes = models.TextField(
        blank=False,
        verbose_name=_('scopes'))

    # metadata
    created = models.DateTimeField(
        verbose_name=_('created'),
        auto_now_add=True)
    expired = models.DateTimeField(
        verbose_name=_('expire'))

    objects = managers.OIDCExpiredManager()

    def scope_set(self):
        return utils.scope_set(self.scopes)

    def __repr__(self):
        return '<OIDCAuthorization client:%r user:%r scopes:%r>' % (
            self.client_id and unicode(self.client),
            self.user_id and unicode(self.user),
            self.scopes)


class OIDCCode(models.Model):
    uuid = models.CharField(
        max_length=128,
        verbose_name=_('uuid'),
        default=generate_uuid)
    client = models.ForeignKey(
        to=OIDCClient,
        verbose_name=_('client'))
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        verbose_name=_('user'))
    scopes = models.TextField(
        verbose_name=_('scopes'))
    state = models.TextField(
        default='',
        verbose_name=_('state'))
    nonce = models.TextField(
        default='',
        verbose_name=_('nonce'))
    redirect_uri = models.URLField(
        verbose_name=_('redirect URI'))
    session_key = models.CharField(
        verbose_name=_('session key'),
        max_length=128)
    auth_time = models.DateTimeField(
        verbose_name=_('auth time'))

    # metadata
    created = models.DateTimeField(
        verbose_name=_('created'),
        auto_now_add=True)
    expired = models.DateTimeField(
        verbose_name=_('expire'))

    objects = managers.OIDCExpiredManager()

    @property
    def session(self):
        if not hasattr(self, '_session'):
            engine = import_module(settings.SESSION_ENGINE)
            session = engine.SessionStore(session_key=self.session_key)
            if session._session_key == self.session_key:
                self._session = session
        return getattr(self, '_session', None)

    def scope_set(self):
        return utils.scope_set(self.scopes)

    def is_valid(self):
        return self.expired >= now() and self.session is not None

    def __repr__(self):
        return '<OIDCAccessToken uuid:%s client:%s user:%s expired:%s scopes:%s>' % (
            self.uuid,
            self.client_id and unicode(self.client),
            self.user_id and unicode(self.user),
            self.expired,
            self.scopes)


class OIDCAccessToken(models.Model):
    uuid = models.CharField(
        max_length=128,
        verbose_name=_('uuid'),
        default=generate_uuid)
    client = models.ForeignKey(
        to=OIDCClient,
        verbose_name=_('client'))
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        verbose_name=_('user'))
    scopes = models.TextField(
        verbose_name=_('scopes'))
    session_key = models.CharField(
        verbose_name=_('session key'),
        max_length=128)

    # metadata
    created = models.DateTimeField(
        verbose_name=_('created'),
        auto_now_add=True)
    expired = models.DateTimeField(
        verbose_name=_('expire'))

    objects = managers.OIDCExpiredManager()

    def scope_set(self):
        return utils.scope_set(self.scopes)

    @property
    def session(self):
        if not hasattr(self, '_session'):
            engine = import_module(settings.SESSION_ENGINE)
            session = engine.SessionStore(session_key=self.session_key)
            if session._session_key == self.session_key:
                self._session = session
        return getattr(self, '_session', None)

    def is_valid(self):
        return self.expired >= now() and self.session is not None

    def __repr__(self):
        return '<OIDCAccessToken uuid:%s client:%s user:%s expired:%s scopes:%s>' % (
            self.uuid,
            self.client_id and unicode(self.client),
            self.user_id and unicode(self.user),
            self.expired,
            self.scopes)
