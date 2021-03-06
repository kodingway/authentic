import sys
import six

from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ImproperlyConfigured


class Setting(object):
    SENTINEL = object()

    def __init__(self, default=SENTINEL, definition='', names=None):
        self.names = names or []
        if isinstance(self.names, six.string_types):
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
                'A2_ACCEPT_EMAIL_AUTHENTICATION', True)

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
                 'authentic2.attributes_ng.sources.django_user',
                 'authentic2.attributes_ng.sources.ldap',
                 'authentic2.attributes_ng.sources.computed_targeted_id',
                 'authentic2.attributes_ng.sources.service_roles',
        ),
        definition='List of attribute backend classes or modules',
    ),
    CAFILE = Setting(names=('AUTHENTIC2_CAFILE', 'CAFILE'),
            default=None,
            definition='File containing certificate chains as PEM certificates'),
    A2_REGISTRATION_URLCONF = Setting(default='authentic2.registration_backend.urls',
                definition='Root urlconf for the /accounts endpoints'),
    A2_REGISTRATION_FORM_CLASS = Setting(default='authentic2.registration_backend.forms.RegistrationForm',
                definition='Default registration form'),
    A2_REGISTRATION_COMPLETION_FORM_CLASS = Setting(default='authentic2.registration_backend.forms.RegistrationCompletionForm',
                definition='Default registration completion form'),
    A2_REGISTRATION_SET_PASSWORD_FORM_CLASS = Setting(default='authentic2.registration_backend.forms.SetPasswordForm',
                definition='Default set password form'),
    A2_REGISTRATION_CHANGE_PASSWORD_FORM_CLASS = Setting(default='authentic2.registration_backend.forms.PasswordChangeForm',
                definition='Default change password form'),
    A2_REGISTRATION_CAN_DELETE_ACCOUNT = Setting(default=True,
                definition='Can user self delete their account and all their data'),
    A2_REGISTRATION_CAN_CHANGE_PASSWORD = Setting(default=True, definition='Allow user to change its own password'),
    A2_REGISTRATION_EMAIL_BLACKLIST = Setting(default=[], definition='List of forbidden email '
                                              'wildcards, ex.: ^.*@ville.fr$'),
    A2_PROFILE_CAN_CHANGE_EMAIL = Setting(default=True,
                definition='Can user self change their email'),
    A2_PROFILE_CAN_EDIT_PROFILE = Setting(default=True,
                definition='Can user self edit their profile'),
    A2_PROFILE_CAN_MANAGE_FEDERATION = Setting(default=True,
                definition='Can user manage its federations'),
    A2_PROFILE_DISPLAY_EMPTY_FIELDS = Setting(default=False,
                definition='Include empty fields in profile view'),
    A2_HOMEPAGE_URL = Setting(default=None, definition='IdP has no homepage, '
        'redirect to this one.'),
    A2_CAN_RESET_PASSWORD = Setting(default=True, definition='Allow online reset of passwords'),
    A2_EMAIL_IS_UNIQUE = Setting(default=False,
        definition='Email of users must be unique'),
    A2_REGISTRATION_EMAIL_IS_UNIQUE = Setting(default=False,
        definition='Email of registererd accounts must be unique'),
    A2_REGISTRATION_FORM_USERNAME_REGEX=Setting(default=r'^[\w.@+-]+$', definition='Regex to validate usernames'),
    A2_REGISTRATION_FORM_USERNAME_HELP_TEXT=Setting(default=_('Required. At most '
        '30 characters. Letters, digits, and @/./+/-/_ only.')),
    A2_REGISTRATION_FORM_USERNAME_LABEL=Setting(default=_('Username')),
    A2_REGISTRATION_REALM=Setting(default=None, definition='Default realm to assign to self-registrated users'),
    A2_REGISTRATION_GROUPS=Setting(default=(), definition='Default groups for self-registered users'),
    A2_PROFILE_FIELDS=Setting(default=(), definition='Fields to show to the user in the profile page'),
    A2_REGISTRATION_FIELDS=Setting(default=(), definition='Fields from the user model that must appear on the registration form'),
    A2_REQUIRED_FIELDS=Setting(default=(), definition='User fields that are required'),
    A2_REGISTRATION_REQUIRED_FIELDS=Setting(default=(), definition='Fields from the registration form that must be required'),
    A2_PRE_REGISTRATION_FIELDS=Setting(default=(), definition='User fields to ask with email'),
    A2_REALMS=Setting(default=(), definition='List of realms to search user accounts'),
    A2_USERNAME_REGEX=Setting(default=None, definition='Regex that username must validate'),
    A2_USERNAME_LABEL=Setting(default=None, definition='Alternate username label for the login'
                              ' form'),
    A2_USERNAME_HELP_TEXT=Setting(default=None, definition='Help text to explain validation rules of usernames'),
    A2_USERNAME_IS_UNIQUE=Setting(default=True, definition='Check username uniqueness'),
    A2_REGISTRATION_USERNAME_IS_UNIQUE=Setting(default=True, definition='Check username uniqueness on registration'),
    IDP_BACKENDS=(),
    AUTH_FRONTENDS=(),
    AUTH_FRONTENDS_KWARGS={},
    VALID_REFERERS=Setting(default=(), definition='List of prefix to match referers'),
    A2_OPENED_SESSION_COOKIE_NAME=Setting(default='A2_OPENED_SESSION', definition='Authentic session open'),
    A2_OPENED_SESSION_COOKIE_DOMAIN=Setting(default=None),
    A2_ATTRIBUTE_KINDS=Setting(default=(), definition='List of other attribute kinds'),
    A2_VALIDATE_EMAIL=Setting(default=False, definition='Validate user email server by doing an RCPT command'),
    A2_VALIDATE_EMAIL_DOMAIN=Setting(default=True, definition='Validate user email domain'),
    A2_PASSWORD_POLICY_MIN_CLASSES=Setting(default=3, definition='Minimum number of characters classes to be present in passwords'),
    A2_PASSWORD_POLICY_MIN_LENGTH=Setting(default=8, definition='Minimum number of characters in a password'),
    A2_PASSWORD_POLICY_REGEX=Setting(default=None, definition='Regular expression for validating passwords'),
    A2_PASSWORD_POLICY_REGEX_ERROR_MSG=Setting(default=None, definition='Error message to show when the password do not validate the regular expression'),
    A2_AUTH_PASSWORD_ENABLE=Setting(default=True, definition='Activate login/password authentication', names=('AUTH_PASSWORD',)),
    A2_LOGIN_FAILURE_COUNT_BEFORE_WARNING=Setting(default=0,
            definition='Failure count before logging a warning to '
            'authentic2.user_login_failure. No warning will be send if value is '
            '0.'),
    PUSH_PROFILE_UPDATES=Setting(default=False, definition='Push profile update to linked services'),
    TEMPLATE_VARS=Setting(default={}, definition='Variable to pass to templates'),
    A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_FACTOR=Setting(default=1.8,
            definition='exponential backoff factor duration as seconds until '
            'next try after a login failure'),
    A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_DURATION=Setting(default=0,
            definition='exponential backoff base factor duration as secondss '
            'until next try after a login failure'),
    A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_MAX_DURATION=Setting(default=3600,
            definition='exponential backoff maximum duration as seconds until '
            'time until next try after a login failure'),
    A2_VERIFY_SSL=Setting(default=True, definition='Verify SSL certificate in HTTP requests'),
    A2_ATTRIBUTE_KIND_TITLE_CHOICES=Setting(default=(), definition='Choices for the title attribute kind'),
    A2_CORS_WHITELIST=Setting(default=(), definition='List of origin URL to whitelist, must be scheme://netloc[:port]'),
    A2_EMAIL_CHANGE_TOKEN_LIFETIME=Setting(default=7200, definition='Lifetime in seconds of the '
                                           'token sent to verify email adresses'),
    A2_REDIRECT_WHITELIST=Setting(
        default=(),
        definition='List of origins which are authorized to ask for redirection.'),
    A2_API_USERS_REQUIRED_FIELDS=Setting(
        default=(),
        definition='List of fields to require on user\'s API, override other settings'),
)

app_settings = AppSettings(default_settings)
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
