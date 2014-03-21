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


    def __getattr__(self, key):
        if key not in self.defaults:
            raise AttributeError('unknown key %s' % key)
        if hasattr(self.settings, key):
            return getattr(self.settings, key)
        if self.defaults[key].names:
            for other_key in self.defaults[other_key].names:
                if hasattr(self.settings, other_key):
                    return getattr(self.settings, other_key)
        if self.defaults[key].has_default():
            return self.defaults[key].default
        raise ImproperlyConfigured('missing setting %s(%s) is mandatory' %
                (key, self.defaults[key].description))


# Registration
default_settings = dict(
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
)

app_settings = AppSettings(default_settings)
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
