# Django settings for authentic project.
import os
import json
import glob
import re

from django.core.exceptions import ImproperlyConfigured
from django.conf import global_settings

from . import plugins

try:
    import yaml
except ImportError:
    yaml = None

gettext_noop = lambda s: s

def to_boolean(name, default=True):
    try:
        value = os.environ[name]
    except KeyError:
        return default
    try:
        i = int(value)
        return bool(i)
    except ValueError:
        if value.lower() in ('true', 't'):
            return True
        if value.lower() in ('false', 'f'):
            return False
    return default

def to_int(name, default):
    try:
        value = os.environ[name]
        return int(value)
    except KeyError:
        return default
    except ValueError:
        raise ImproperlyConfigured('environ variable %s must be an integer' % name)


DEBUG = 'DEBUG' in os.environ
DEBUG_PROPAGATE_EXCEPTIONS = 'DEBUG_PROPAGATE_EXCEPTIONS' in os.environ
USE_DEBUG_TOOLBAR = 'USE_DEBUG_TOOLBAR' in os.environ
TEMPLATE_DEBUG = DEBUG

BASE_DIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.join(BASE_DIR, '..')
PROJECT_NAME = 'authentic2'
VAR_DIR = os.path.join('/var/lib/', PROJECT_NAME)
ETC_DIR = os.path.join('/etc', PROJECT_NAME)

ADMINS = ()
if 'ADMINS' in os.environ:
    ADMINS = filter(None, os.environ.get('ADMINS').split(':'))
    ADMINS = [ admin.split(';') for admin in ADMINS ]
    for admin in ADMINS:
        assert len(admin) == 2, 'ADMINS setting must be a colon separated list of name and emails separated by a semi-colon'
        assert '@' in admin[1], 'ADMINS setting pairs second value must be emails'

MANAGERS = ADMINS


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(PROJECT_DIR, PROJECT_NAME + '.db'),
    }
}

for key in os.environ:
    if key.startswith('DATABASE_'):
        prefix, db_key = key.split('_', 1)
        DATABASES['default'][db_key] = os.environ[key]

# Hey Entr'ouvert is in France !!
TIME_ZONE = 'Europe/Paris'
LANGUAGE_CODE = 'fr'
USE_I18N = True
USE_L10N = True

# Static files

STATIC_ROOT = os.environ.get('STATIC_ROOT', os.path.join(VAR_DIR, 'static'))
STATIC_URL = os.environ.get('STATIC_URL', '/static/')

if DEBUG:
    TEMPLATE_LOADERS = (
        'django.template.loaders.filesystem.Loader',
        'django.template.loaders.app_directories.Loader',
    )
else:
    TEMPLATE_LOADERS = (
        ('django.template.loaders.cached.Loader', (
            'django.template.loaders.filesystem.Loader',
            'django.template.loaders.app_directories.Loader',)),
    )

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.request',
    'django.contrib.messages.context_processors.messages',
    'django.core.context_processors.static',
    'authentic2.context_processors.a2_processor',
)

MIDDLEWARE_CLASSES = (
    'authentic2.middleware.LoggingCollectorMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.http.ConditionalGetMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.transaction.TransactionMiddleware',
    'authentic2.idp.middleware.DebugMiddleware',
    'authentic2.middleware.CollectIPMiddleware',
)

A2_OPENED_SESSION_COOKIE_DOMAIN = os.environ.get('A2_OPENED_SESSION_COOKIE_DOMAIN')
if A2_OPENED_SESSION_COOKIE_DOMAIN:
    MIDDLEWARE_CLASSES += (
        'authentic2.middleware.OpenedSessionCookieMiddleware',
    )

MIDDLEWARE_CLASSES = plugins.register_plugins_middleware(MIDDLEWARE_CLASSES)

ROOT_URLCONF = 'authentic2.urls'

TEMPLATE_DIRS = (
        os.path.join(VAR_DIR, 'templates'),
        os.path.join(BASE_DIR, 'templates'),
)

STATICFILES_DIRS = (
        os.path.join(VAR_DIR, 'extra-static'),
        os.path.join(BASE_DIR, 'static'),
)

if os.environ.get('TEMPLATE_DIRS'):
    TEMPLATE_DIRS = tuple(os.environ['TEMPLATE_DIRS'].split(':')) + TEMPLATE_DIRS

TEMPLATE_VARS = {}

if os.environ.get('STATICFILES_DIRS'):
    STATICFILES_DIRS = tuple(os.environ['STATICFILES_DIRS'].split(':')) + STATICFILES_DIRS

LOCALE_PATHS = (
        os.path.join(VAR_DIR, 'locale'),
        os.path.join(BASE_DIR, 'locale'),
)
if os.environ.get('LOCALE_PATHS'):
    LOCALE_PATHS = tuple(os.environ['LOCALE_PATHS'].split(':')) + LOCALE_PATHS



INSTALLED_APPS = (
    'django.contrib.staticfiles',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'south',
    'admin_tools',
    'admin_tools.theming',
    'admin_tools.menu',
    'admin_tools.dashboard',
    'django.contrib.admin',
    'registration',
    'authentic2.nonce',
    'authentic2.saml',
    'authentic2.idp',
    'authentic2.idp.saml',
    'authentic2.auth2_auth',
    'authentic2.attribute_aggregator',
    'authentic2.disco_service',
    'authentic2',
)

INSTALLED_APPS = plugins.register_plugins_installed_apps(INSTALLED_APPS)

MESSAGE_STORAGE = 'django.contrib.messages.storage.session.SessionStorage'



# authentication
AUTHENTICATION_BACKENDS = (
    'authentic2.backends.ModelBackend',
)
AUTHENTICATION_BACKENDS = plugins.register_plugins_authentication_backends(
        AUTHENTICATION_BACKENDS)

# sessions
SESSION_EXPIRE_AT_BROWSER_CLOSE =  'SESSION_EXPIRE_AT_BROWSER_CLOSE' in os.environ
SESSION_COOKIE_AGE = int(os.environ.get('SESSION_COOKIE_AGE', 36000)) # one day of work
SESSION_COOKIE_NAME = os.environ.get('SESSION_COOKIE_NAME', 'sessionid')
SESSION_COOKIE_PATH = os.environ.get('SESSION_COOKIE_PATH', '/')
SESSION_COOKIE_SECURE = 'SESSION_COOKIE_SECURE' in os.environ
if 'SESSION_ENGINE' in os.environ:
    SESSION_ENGINE = os.environ['SESSION_ENGINE']

# email settings
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'localhost')
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 25))
EMAIL_SUBJECT_PREFIX = os.environ.get('EMAIL_SUBJECT_PREFIX', '[Authentic]')
EMAIL_USE_TLS = 'EMAIL_USE_TLS' in os.environ
SERVER_EMAIL = os.environ.get('SERVER_EMAIL', 'root@localhost')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'webmaster@localhost')

# web & network settings
if 'ALLOWED_HOSTS' in os.environ:
    ALLOWED_HOSTS = os.environ['ALLOWED_HOSTS'].split(':')
USE_X_FORWARDED_HOST = 'USE_X_FORWARDED_HOST' in os.environ
if 'SECURE_PROXY_SSL_HEADER' in os.environ:
    SECURE_PROXY_SSL_HEADER = os.environ['SECURE_PROXY_SSL_HEADER'].split(':', 1)
LOGIN_REDIRECT_URL = os.environ.get('LOGIN_REDIRECT_URL', '/')
LOGIN_URL = os.environ.get('LOGIN_URL', '/login')
LOGOUT_URL = os.environ.get('LOGOUT_URL', '/accounts/logout')

if 'INTERNAL_IPS' in os.environ:
    INTERNAL_IPS = os.environ['INTERNAL_IPS'].split(':')
else:
    INTERNAL_IPS = ('127.0.0.1',)

# misc
SECRET_KEY = os.environ.get('SECRET_KEY', '0!=(1kc6kri-ui+tmj@mr+*0bvj!(p*r0duu2n=)7@!p=pvf9n')
DEBUG_TOOLBAR_CONFIG = {'INTERCEPT_REDIRECTS': False}

# Authentic2 settings

DISCO_SERVICE = 'DISCO_SERVICE' in os.environ
DISCO_USE_OF_METADATA = 'DISCO_USE_OF_METADATA' in os.environ

DISCO_SERVICE_NAME = os.environ.get('DISCO_SERVICE_NAME', "http://www.identity-hub.com/disco_service/disco")
DISCO_RETURN_ID_PARAM = "entityID"
SHOW_DISCO_IN_MD = 'SHOW_DISCO_IN_MD' in os.environ

###########################
# Authentication settings
###########################

# Only RSA private keys are currently supported
AUTH_FRONTENDS = ( 'authentic2.auth_frontends.LoginPasswordBackend',)
AUTH_FRONTENDS = plugins.register_plugins_auth_frontends(AUTH_FRONTENDS)
SSLAUTH_CREATE_USER = 'SSLAUTH_CREATE_USER' in os.environ
AUTHENTICATION_EVENT_EXPIRATION = int(os.environ.get('AUTHENTICATION_EVENT_EXPIRATION', 3600*24*7))

#############################
# Identity Provider settings
#############################

# List of IdP backends, mainly used to show available services in the homepage
# of user, and to handle SLO for each protocols
IDP_BACKENDS = plugins.register_plugins_idp_backends(())

# You MUST changes these keys, they are just for testing !
LOCAL_METADATA_CACHE_TIMEOUT = int(os.environ.get('LOCAL_METADATA_CACHE_TIMEOUT', 600))
SAML_SIGNATURE_PUBLIC_KEY = os.environ.get('SAML_SIGNATURE_PUBLIC_KEY', '''-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIJANUBoick1pDpMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNV
BAoTCkVudHJvdXZlcnQwHhcNMTAxMjE0MTUzMzAyWhcNMTEwMTEzMTUzMzAyWjAV
MRMwEQYDVQQKEwpFbnRyb3V2ZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAvxFkfPdndlGgQPDZgFGXbrNAc/79PULZBuNdWFHDD9P5hNhZn9Kqm4Cp
06Pe/A6u+g5wLnYvbZQcFCgfQAEzziJtb3J55OOlB7iMEI/T2AX2WzrUH8QT8NGh
ABONKU2Gg4XiyeXNhH5R7zdHlUwcWq3ZwNbtbY0TVc+n665EbrfV/59xihSqsoFr
kmBLH0CoepUXtAzA7WDYn8AzusIuMx3n8844pJwgxhTB7Gjuboptlz9Hri8JRdXi
VT9OS9Wt69ubcNoM6zuKASmtm48UuGnhj8v6XwvbjKZrL9kA+xf8ziazZfvvw/VG
Tm+IVFYB7d1x457jY5zjjXJvNysoowIDAQABo3YwdDAdBgNVHQ4EFgQUeF8ePnu0
fcAK50iBQDgAhHkOu8kwRQYDVR0jBD4wPIAUeF8ePnu0fcAK50iBQDgAhHkOu8mh
GaQXMBUxEzARBgNVBAoTCkVudHJvdXZlcnSCCQDVAaInJNaQ6TAMBgNVHRMEBTAD
AQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAy8l3GhUtpPHx0FxzbRHVaaUSgMwYKGPhE
IdGhqekKUJIx8et4xpEMFBl5XQjBNq/mp5vO3SPb2h2PVSks7xWnG3cvEkqJSOeo
fEEhkqnM45b2MH1S5uxp4i8UilPG6kmQiXU2rEUBdRk9xnRWos7epVivTSIv1Ncp
lG6l41SXp6YgIb2ToT+rOKdIGIQuGDlzeR88fDxWEU0vEujZv/v1PE1YOV0xKjTT
JumlBc6IViKhJeo1wiBBrVRIIkKKevHKQzteK8pWm9CYWculxT26TZ4VWzGbo06j
o2zbumirrLLqnt1gmBDvDvlOwC/zAAyL4chbz66eQHTiIYZZvYgy
-----END CERTIFICATE-----''')

SAML_SIGNATURE_PRIVATE_KEY = os.environ.get('SAML_SIGNATURE_PRIVATE_KEY', '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvxFkfPdndlGgQPDZgFGXbrNAc/79PULZBuNdWFHDD9P5hNhZ
n9Kqm4Cp06Pe/A6u+g5wLnYvbZQcFCgfQAEzziJtb3J55OOlB7iMEI/T2AX2WzrU
H8QT8NGhABONKU2Gg4XiyeXNhH5R7zdHlUwcWq3ZwNbtbY0TVc+n665EbrfV/59x
ihSqsoFrkmBLH0CoepUXtAzA7WDYn8AzusIuMx3n8844pJwgxhTB7Gjuboptlz9H
ri8JRdXiVT9OS9Wt69ubcNoM6zuKASmtm48UuGnhj8v6XwvbjKZrL9kA+xf8ziaz
Zfvvw/VGTm+IVFYB7d1x457jY5zjjXJvNysoowIDAQABAoIBAQCj8t2iKXya10HG
V6Saaeih8aftoLBV38VwFqqjPU0+iKqDpk2JSXBhjI6s7uFIsaTNJpR2Ga1qvns1
hJQEDMQSLhJvXfBgSkHylRWCpJentr4E3D7mnw5pRsd61Ev9U+uHcdv/WHP4K5hM
xsdiwXNXD/RYd1Q1+6bKrCuvnNJVmWe0/RV+r3T8Ni5xdMVFbRWt/VEoE620XX6c
a9TQPiA5i/LRVyie+js7Yv+hVjGOlArtuLs6ECQsivfPrqKLOBRWcofKdcf+4N2e
3cieUqwzC15C31vcMliD9Hax9c1iuTt9Q3Xzo20fOSazAnQ5YBEExyTtrFBwbfQu
ku6hp81pAoGBAN6bc6iJtk5ipYpsaY4ZlbqdjjG9KEXB6G1MExPU7SHXOhOF0cDH
/pgMsv9hF2my863MowsOj3OryVhdQhwA6RrV263LRh+JU8NyHV71BwAIfI0BuVfj
6r24KudwtUcvMr9pJIrJyMAMaw5ZyNoX7YqFpS6fcisSJYdSBSoxzrzVAoGBANu6
xVeMqGavA/EHSOQP3ipDZ3mnWbkDUDxpNhgJG8Q6lZiwKwLoSceJ8z0PNY3VetGA
RbqtqBGfR2mcxHyzeqVBpLnXZC4vs/Vy7lrzTiHDRZk2SG5EkHMSKFA53jN6S/nJ
JWpYZC8lG8w4OHaUfDHFWbptxdGYCgY4//sjeiuXAoGBANuhurJ99R5PnA8AOgEW
4zD1hLc0b4ir8fvshCIcAj9SUB20+afgayRv2ye3Dted1WkUL4WYPxccVhLWKITi
rRtqB03o8m3pG3kJnUr0LIzu0px5J/o8iH3ZOJOTE3iBa+uI/KHmxygc2H+XPGFa
HGeAxuJCNO2kAN0Losbnz5dlAoGAVsCn94gGWPxSjxA0PC7zpTYVnZdwOjbPr/pO
LDE0cEY9GBq98JjrwEd77KibmVMm+Z4uaaT0jXiYhl8pyJ5IFwUS13juCbo1z/u/
ldMoDvZ8/R/MexTA/1204u/mBecMJiO/jPw3GdIJ5phv2omHe1MSuSNsDfN8Sbap
gmsgaiMCgYB/nrTk89Fp7050VKCNnIt1mHAcO9cBwDV8qrJ5O3rIVmrg1T6vn0aY
wRiVcNacaP+BivkrMjr4BlsUM6yH4MOBsNhLURiiCL+tLJV7U0DWlCse/doWij4U
TKX6tp6oI+7MIJE6ySZ0cBqOiydAkBePZhu57j6ToBkTa0dbHjn1WA==
-----END RSA PRIVATE KEY-----''')

# Whether to autoload SAML 2.0 identity providers and services metadata
# Only https URLS are accepted.
# Can be none, sp, idp or both
SAML_METADATA_AUTOLOAD = os.environ.get('SAML_METADATA_AUTOLOAD', 'none')

PUSH_PROFILE_UPDATES = 'PUSH_PROFILE_UPDATES' in os.environ


if 'PASSWORD_HASHERS' in os.environ:
    PASSWORD_HASHERS = os.environ['PASSWORD_HASHERS'].split(':')
else:
    PASSWORD_HASHERS = global_settings.PASSWORD_HASHERS
    PASSWORD_HASHERS += (
            'authentic2.hashers.Drupal7PasswordHasher',
            'authentic2.hashers.SHA256PasswordHasher',
            'authentic2.hashers.SSHA1PasswordHasher',
            'authentic2.hashers.SMD5PasswordHasher',
            'authentic2.hashers.SHA1OLDAPPasswordHasher',
            'authentic2.hashers.MD5OLDAPPasswordHasher',
    )

##################################
# LDAP Configuration
##################################
if 'LDAP_AUTH_SETTINGS' in os.environ:
    try:
        LDAP_AUTH_SETTINGS = json.loads(os.environ['LDAP_AUTH_SETTINGS'])
    except Exception, e:
        raise ImproperlyConfigured('LDAP_AUTH_SETTINGS is not a JSON document', e)
else:
    LDAP_AUTH_SETTINGS = []
##################################
# Cache configuration
##################################
CACHE_DIR = os.path.join('/var/cache/', PROJECT_NAME)
if not os.access(CACHE_DIR, os.W_OK):
    CACHE_DIR = os.path.join(PROJECT_DIR, 'cache')
    print 'Cannot access global cache path, using in project cache directory', CACHE_DIR
    if not os.path.isdir(CACHE_DIR):
        os.makedirs(CACHE_DIR)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': CACHE_DIR,
    },
}
if 'CACHE_BACKEND' in os.environ:
    CACHES['default'] = json.loads(os.environ['CACHE_BACKEND'])

if 'USE_MEMCACHED' in os.environ:
    CACHES = {
            'default': {
                'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
                'LOCATION': '127.0.0.1:11211',
                'KEY_PREFIX': 'authentic2',
                }
            }
    SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'

# Logging settings

# add sentry handler if environment contains SENTRY_DSN
if 'SENTRY_DSN' in os.environ:
    try:
        import raven
    except ImportError:
        raise ImproperlyConfigured('SENTRY_DSN environment variable is set but raven is not installed.')
    SENTRY_DSN = os.environ['SENTRY_DSN']

else:
    SENTRY_DSN = None

SOUTH_TESTS_MIGRATE = False

############################
# Registration
############################
A2_ACCEPT_EMAIL_AUTHENTICATION = to_boolean('A2_ACCEPT_EMAIL_AUTHENTICATION')
A2_CAN_RESET_PASSWORD = to_boolean('A2_CAN_RESET_PASSWORD')
A2_REGISTRATION_CAN_DELETE_ACCOUNT = to_boolean('A2_REGISTRATION_CAN_DELETE_ACCOUNT')
A2_REGISTRATION_EMAIL_IS_UNIQUE = to_boolean('A2_REGISTRATION_EMAIL_IS_UNIQUE', default=False)
REGISTRATION_OPEN = to_boolean('REGISTRATION_OPEN')
ACCOUNT_ACTIVATION_DAYS = to_int('ACCOUNT_ACTIVATION_DAYS', 3)
PASSWORD_RESET_TIMEOUT_DAYS = to_int('PASSWORD_RESET_TIMEOUT_DAYS', 3)

if 'A2_HOMEPAGE_URL' in os.environ:
    A2_HOMEPAGE_URL = os.environ['A2_HOMEPAGE_URL']

# Admin tools
ADMIN_TOOLS_INDEX_DASHBOARD = 'authentic2.dashboard.CustomIndexDashboard'
ADMIN_TOOLS_APP_INDEX_DASHBOARD = 'authentic2.dashboard.CustomAppIndexDashboard'
ADMIN_TOOLS_MENU = 'authentic2.menu.CustomMenu'

AUTH_OPENID = 'AUTH_OPENID' in os.environ
AUTH_SSL = 'AUTH_SSL' in os.environ
IDP_SAML2 = 'IDP_SAML2' in os.environ
IDP_OPENID = 'IDP_OPENID' in os.environ

# extract any key starting with setting
for key in os.environ:
    if key.startswith('SETTING_'):
        setting_key = key[len('SETTING_'):]
        value = os.environ[key]
        try:
             value = int(value)
        except ValueError:
             pass
        globals()[setting_key] = value

# Remove after Django 1.7
SERIALIZATION_MODULES = {
        'json': 'authentic2.serializers',
}

DEBUG_LOG = os.environ.get('DEBUG_LOG')

def load_dict_config(d):
    for key in d:
        if re.match('^[A-Z][_A-Z0-9]*$', key):
            globals()[key] = d[key]

CONFIG_DIRS = [ETC_DIR]
if 'CONFIG_DIRS' in os.environ:
    CONFIG_DIRS += os.environ['CONFIG_DIRS'].split(':')

if yaml:
    for config_dir in CONFIG_DIRS:
        wildcard = os.path.join(config_dir, '*.yaml')
        for path in sorted(glob.glob(wildcard)):
            yaml_config = yaml.load(file(path))
            if not isinstance(yaml_config, dict):
                raise ImproperlyConfigured('YAML file %r is not a dictionnary' % path)
            load_dict_config(yaml_config)

for config_dir in CONFIG_DIRS:
    wildcard = os.path.join(config_dir, '*.json')
    for path in sorted(glob.glob(wildcard)):
        json_config = json.load(file(path))
        if not isinstance(json_config, dict):
            raise ImproperlyConfigured('JSON file %r is not a dictionnary' % path)
        load_dict_config(json_config)

for config_dir in CONFIG_DIRS:
    config_py = os.path.join(config_dir, 'config.py')
    if os.path.exists(config_py):
        execfile(config_py, globals())

try:
    from local_settings import *
except ImportError, e:
    if 'local_settings' in e.args[0]:
        pass

from . import fix_user_model

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'cleaning': {
            '()':  'authentic2.utils.CleanLogMessage',
        },
    },
    'formatters': {
        'verbose': {
            'format': '[%(asctime)s] %(levelname)s %(name)s: %(message)s',
            'datefmt': '%Y-%m-%d %a %H:%M:%S'
        },
        'syslog': {
            'format': '%(levelname)s %(name)s: %(message)s',
        },
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class':'django.utils.log.NullHandler',
        },
        'console': {
            'level': 'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'verbose',
            'filters': ['cleaning'],
        },
        'syslog': {
            'level': 'DEBUG',
            'address': '/dev/log',
            'class': 'logging.handlers.SysLogHandler',
            'filters': ['cleaning'],
            'formatter': 'syslog',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'include_html': True,
            'filters': ['cleaning'],
        }
    },
    'loggers': {
        # disable default handlers
        'django.request': {
            'handlers': [],
            'propagate': True,
        },
        'django.db': {
            'handlers': ['null'],
            'propagate': True,
        },
        '': {
                'handlers': ['mail_admins', 'syslog'],
                'level': 'INFO',
        }
    },
}

if DEBUG and not DEBUG_LOG:
    LOGGING['loggers']['']['handlers'] += ['console']
    LOGGING['loggers']['']['level'] = 'DEBUG'

if DEBUG_LOG:
    domains = DEBUG_LOG.split()
    for domain in domains:
        logger = LOGGING['loggers'].setdefault(domain, {
                'handlers': ['mail_admins', 'syslog'],
                'level': 'DEBUG',
        })
        if 'syslog' not in logger['handlers']:
            logger['handlers'] += ['syslog']
        if 'console' not in logger['handlers']:
            logger['handlers'] += ['console']
        logger['level'] = 'DEBUG'

if SENTRY_DSN is not None:
    try:
        import raven
    except ImportError:
        raise ImproperlyConfigured('SENTRY_DSN present but raven is not installed')
    RAVEN_CONFIG = {
            'dsn': SENTRY_DSN,
            }
    INSTALLED_APPS += ('raven.contrib.django.raven_compat', )
    LOGGING['handlers']['sentry'] = {
            'level': 'ERROR',
            'class': 'raven.contrib.django.raven_compat.handlers.SentryHandler',
            }
    LOGGING['loggers']['']['handlers'].append('sentry')

if USE_DEBUG_TOOLBAR:
    try:
        import debug_toolbar
        MIDDLEWARE_CLASSES += ('debug_toolbar.middleware.DebugToolbarMiddleware',)
        INSTALLED_APPS += ('debug_toolbar',)
    except ImportError:
        print "Debug toolbar missing, not loaded"

if AUTH_OPENID:
    INSTALLED_APPS += ('authentic2.auth2_auth.auth2_openid', 'django_authopenid',)
    AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_openid.backend.OpenIDFrontend',)

if AUTH_SSL:
    AUTHENTICATION_BACKENDS += ('authentic2.auth2_auth.auth2_ssl.backend.SSLBackend',)
    AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_ssl.frontend.SSLFrontend',)
    INSTALLED_APPS += ('authentic2.auth2_auth.auth2_ssl',)

if IDP_SAML2:
    IDP_BACKENDS += ('authentic2.idp.saml.backend.SamlBackend',)

if IDP_OPENID:
    # RESTRICT_OPENID_RP = ["http://rp.example.com", ] # orequest.trust_root
    INSTALLED_APPS += ('authentic2.idp.idp_openid',)
    TEMPLATE_CONTEXT_PROCESSORS += ('authentic2.idp.idp_openid.context_processors.openid_meta',)
    # OPENID_ACTIONS = {"http://rp.example.com" : 'my-template.html', }

if LDAP_AUTH_SETTINGS:
    AUTHENTICATION_BACKENDS = ('authentic2.backends.LDAPBackend',) + AUTHENTICATION_BACKENDS

if DEBUG:
    print 'Debugging mode is active'
