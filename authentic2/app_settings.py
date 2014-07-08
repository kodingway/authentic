import sys

from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ImproperlyConfigured


class Setting(object):
    SENTINEL = object()

    def __init__(self, default=SENTINEL, definition='', names=None):
        self.names = names or []
        if isinstance(self.names, basestring):
            self.names = [self.names]
        self.names = set(self.names)
        self.default = default
        self.definition = definition

    def has_default(self):
        return self.default != self.SENTINEL

class AppSettings(object):
    def __init__(self, defaults):
        self.defaults = defaults

    @property
    def settings(self):
        if not hasattr(self, '_settings'):
            from django.conf import settings
            self._settings = settings
        return self._settings

    @property
    def ACCEPT_EMAIL_AUTHENTICATION(self):
        return getattr(self.settings,
                'A2_ACCEPT_EMAIL_AUTHENTICATION', False)

    @property
    def REALMS(self):
        realms = {}
        if self.A2_REGISTRATION_REALM:
            realms[self.A2_REGISTRATION_REALM] = self.A2_REGISTRATION_REALM
        def add_realms(new_realms):
            for realm in new_realms:
                if not isinstance(realm, (tuple, list)):
                    realms[realm] = realm
                else:
                    realms[realm[0]] = realm[1]
        from django.contrib.auth import get_backends
        for backend in get_backends():
            if hasattr(backend, 'get_realms'):
                add_realms(backend.get_realms())
        if self.A2_REALMS:
            add_realms(self.A2_REALMS)
        return realms.items()

    def __getattr__(self, key):
        if key not in self.defaults:
            raise AttributeError('unknown key %s' % key)
        if hasattr(self.settings, key):
            return getattr(self.settings, key)
        if self.defaults[key].names:
            for other_key in self.defaults[key].names:
                if hasattr(self.settings, other_key):
                    return getattr(self.settings, other_key)
        if self.defaults[key].has_default():
            return self.defaults[key].default
        raise ImproperlyConfigured('missing setting %s(%s) is mandatory' %
                (key, self.defaults[key].description))


# Registration
default_settings = dict(
    ATTRIBUTE_BACKENDS = Setting(
        names=('A2_ATTRIBUTE_BACKENDS',),
        default=('authentic2.attributes_ng.sources.format',
                 'authentic2.attributes_ng.sources.function',
                 'authentic2.attributes_ng.sources.django_user',),
        definition='List of attribute backend classes or modules',
    ),
    CAFILE = Setting(names=('AUTHENTIC2_CAFILE', 'CAFILE'),
            default='/etc/ssl/certs/ca-certificates.crt',
            definition='File containing certificate chains as PEM certificates'),
    CAPATH = Setting(names=('AUTHENTIC2_CAPATH', 'CAPATH'), default='/etc/ssl/certs/',
            definition='Directory containing PEM certificates named'
            ' using OpenSSL certificate directory convention. '
            'See http://www.openssl.org/docs/apps/verify.html#item__CApath'),
    A2_REGISTRATION_URLCONF = Setting(default='authentic2.registration_backend.urls',
                definition='Root urlconf for the /accounts endpoints'),
    A2_REGISTRATION_FORM_CLASS = Setting(default='authentic2.registration_backend.forms.RegistrationForm',
                definition='Default registration form'),
    A2_REGISTRATION_SET_PASSWORD_FORM_CLASS = Setting(default='django.contrib.auth.forms.SetPasswordForm',
                definition='Default set password form'),
    A2_REGISTRATION_CHANGE_PASSWORD_FORM_CLASS = Setting(default='django.contrib.auth.forms.PasswordChangeForm',
                definition='Default change password form'),
    A2_REGISTRATION_CAN_DELETE_ACCOUNT = Setting(default=True,
                definition='Can user self delete their account and all their data'),
    A2_HOMEPAGE_URL = Setting(default=None, definition='IdP has no homepage, '
        'redirect to this one.'),
    A2_CAN_RESET_PASSWORD = Setting(default=True, definition='Allow online reset of passwords'),
    A2_REGISTRATION_EMAIL_IS_UNIQUE = Setting(default=False,
        definition='Email of accounts must be unique'),
    A2_REGISTRATION_FORM_USERNAME_REGEX=Setting(default=r'^[\w.@+-]+$', definition='Regex to validate usernames'),
    A2_REGISTRATION_FORM_USERNAME_HELP_TEXT=Setting(default=_('Required. At most '
        '30 characters. Letters, digits, and @/./+/-/_ only.')),
    A2_REGISTRATION_FORM_USERNAME_LABEL=Setting(default=_('Username')),
    A2_REGISTRATION_REALM=Setting(default=None, definition='Default realm to assign to self-registrated users'),
    A2_REGISTRATION_GROUPS=Setting(default=[], definition='Default groups for self-registered users'),
    A2_PROFILE_FIELDS=Setting(default=[], definition='Fields to show to the user in the profile page'),
    A2_REGISTRATION_FIELDS=Setting(default=[], definition='Fields from the user model that must appear on the registration form'),
    A2_REGISTRATION_REQUIRED_FIELDS=Setting(default=[], definition='Fields from the registration form that must be required'),
    A2_REALMS=Setting(default=[], definition='List of realms to search user accounts'),
    A2_USERNAME_REGEX=Setting(default=None, definition='Regex that username must validate'),
    A2_USERNAME_HELP_TEXT=Setting(default=None, definition='Help text to explain validation rules of usernames'),
    IDP_BACKENDS=[],
    AUTH_FRONTENDS=[],
    VALID_REFERERS=Setting(default=[], definition='List of prefix to match referers'),
    A2_OPENED_SESSION_COOKIE_NAME=Setting(default='A2_OPENED_SESSION', definition='Authentic session open'),
    A2_OPENED_SESSION_COOKIE_DOMAIN=Setting(default=None),
    A2_ATTRIBUTE_KINDS=Setting(default=[], definition='List of other attribute kinds'),
)

app_settings = AppSettings(default_settings)
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
