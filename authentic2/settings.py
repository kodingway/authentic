# Django settings for authentic project.
import os

gettext_noop = lambda s: s

DEBUG = 'DEBUG' in os.environ
DEBUG_PROPAGATE_EXCEPTIONS = 'DEBUG_PROPAGATE_EXCEPTIONS' in os.environ
USE_DEBUG_TOOLBAR = 'USE_DEBUG_TOOLBAR' in os.environ
TEMPLATE_DEBUG = DEBUG

_PROJECT_PATH = os.path.join(os.path.dirname(__file__), '..')

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
        'ENGINE': os.environ.get('DATABASE_ENGINE', 'django.db.backends.sqlite3'),
        'NAME': os.environ.get('DATABASE_NAME', os.path.join(_PROJECT_PATH, 'authentic.db')),
    }
}

# Hey Entr'ouvert is in France !!
TIME_ZONE = 'Europe/Paris'
LANGUAGE_CODE = 'fr'
SITE_ID = 1
USE_I18N = True

LANGUAGES = (
    ('en', gettext_noop('English')),
    ('fr', gettext_noop('French')),
)
USE_L10N = True

# Static files

STATIC_ROOT = os.environ.get('STATIC_ROOT', '/var/lib/authentic2/static')
STATIC_URL = os.environ.get('STATIC_URL', '/static/')
if 'STATICFILES_DIRS' in os.environ:
    STATICFILES_DIRS = os.environ['STATICFILES_DIRS'].split(':')
else:
    STATICFILES_DIRS = ('/var/lib/authentic2/extra-static/',)

TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.request',
    'django.contrib.messages.context_processors.messages',
    'django.core.context_processors.static',
    'authentic2.context_processors.federations_processor',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.middleware.http.ConditionalGetMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.transaction.TransactionMiddleware',
    'authentic2.idp.middleware.DebugMiddleware'
)

ROOT_URLCONF = 'authentic2.urls'

if os.environ.get('TEMPLATE_DIRS'):
    TEMPLATE_DIRS = os.environ['TEMPLATE_DIRS'].split(':')
else:
    TEMPLATE_DIRS = ('/var/lib/authentic2/templates',)


INSTALLED_APPS = (
    'authentic2',
    'authentic2.nonce',
    'authentic2.saml',
    'authentic2.idp',
    'authentic2.idp.saml',
    'admin_tools',
    'admin_tools.theming',
    'admin_tools.menu',
    'admin_tools.dashboard',
    'django.contrib.staticfiles',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.admin',
    'django.contrib.sites',
    'registration',
    'authentic2.auth2_auth',
    'south',
    'authentic2.attribute_aggregator',
    'authentic2.disco_service',
)

MESSAGE_STORAGE = 'django.contrib.messages.storage.session.SessionStorage'


# Registration settings
ACCOUNT_ACTIVATION_DAYS = int(os.environ.get('ACCOUNT_ACTIVATION_DAYS', 3))
PASSWORD_RESET_TIMEOUT_DAYS = int(os.environ.get('PASSWORD_RESET_TIMEOUT_DAYS', 3))

# sessions
SESSION_EXPIRE_AT_BROWSER_CLOSE =  'SESSION_EXPIRE_AT_BROWSER_CLOSE' in os.environ
SESSION_COOKIE_AGE = int(os.environ.get('SESSION_COOKIE_AGE', 36000)) # one day of work
SESSION_COOKIE_NAME = os.environ.get('SESSION_COOKIE_NAME', 'sessionid')
SESSION_COOKIE_PATH = os.environ.get('SESSION_COOKIE_PATH', '/')
SESSION_COOKIE_SECURE = 'SESSION_COOKIE_SECURE' in os.environ

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
    ALLOWED_HOSTS = os.environg['ALLOWED_HOSTS'].split(':')
USE_X_FORWARDED_HOST = 'USE_X_FORWARDED_HOST' in os.environ
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
USE_DISCO_SERVICE = 'USE_DISCO_SERVICE' in os.environ

###########################
# Authentication settings
###########################

# Only RSA private keys are currently supported
AUTH_FRONTENDS = ( 'authentic2.auth2_auth.backend.LoginPasswordBackend',)

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
)
AUTH_USER_MODEL = 'authentic2.User'

# expiration in seconds of authentication events.
# default: 1 week
# AUTHENTICATION_EVENT_EXPIRATION = 3600*24*7

# SSL Authentication
AUTH_SSL = False
SSLAUTH_CREATE_USER = True

# SAML2 Authentication
AUTH_SAML2 = True

# OpenID Authentication
AUTH_OPENID = False

# OATH Authentication
AUTH_OATH = False

#############################
# Identity Provider settings
#############################

# List of IdP backends, mainly used to show available services in the homepage
# of user, and to handle SLO for each protocols
IDP_BACKENDS = [ ]

# SAML2 IDP
IDP_SAML2 = True

# You MUST changes these keys, they are just for testing !
LOCAL_METADATA_CACHE_TIMEOUT = 600
SAML_SIGNATURE_PUBLIC_KEY = '''-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----'''

SAML_SIGNATURE_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----'''

SAML_METADATA_ROOT = 'metadata'
# Whether to autoload SAML 2.0 identity providers and services metadata
# Only https URLS are accepted.
# Can be none, sp, idp or both
SAML_METADATA_AUTOLOAD = 'none'

# OpenID settings
# Requires python-openid
IDP_OPENID = False

# CAS settings
IDP_CAS = False
# expiration time in seconds of the cas tickets
# CAS_TICKET_EXPIRATION = 240

PUSH_PROFILE_UPDATES = False

# Logging settings

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'filters': {
        'cleaning': {
            '()':  'authentic2.utils.CleanLogMessage',
        },
    },
    'formatters': {
        'verbose': {
            'format': '[%(asctime)s] %(levelname)-8s %(name)s.%(message)s',
            'datefmt': '%Y-%m-%d %a %H:%M:%S'
        },
    },
    'handlers': {
        'null': {
            'level':'DEBUG',
            'class':'django.utils.log.NullHandler',
        },
        'console': {
            'level':'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'verbose',
            'filters': ['cleaning'],
        },
        'local_file': {
            'level':'DEBUG',
            'class':'logging.FileHandler',
            'formatter': 'verbose',
            'filename': os.environ.get('LOG_ROOT', os.path.join(_PROJECT_PATH, 'log.log')),
            'filters': ['cleaning'],
        },
        'syslog': {
            'level':'INFO',
            'class':'logging.handlers.SysLogHandler',
            'filters': ['cleaning'],
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'include_html': True,
            'filters': ['cleaning'],
        }
    },
    'loggers': {
        'django': {
            'handlers':['null'],
            'propagate': True,
            'level':'INFO',
        },
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': False,
        },
        '': {
                'handlers': ['local_file'] + (['console'] if DEBUG else []),
                'level': 'INFO',
        }
    },
}

SOUTH_TESTS_MIGRATE = False

# Admin tools
ADMIN_TOOLS_INDEX_DASHBOARD = 'authentic2.dashboard.CustomIndexDashboard'
ADMIN_TOOLS_APP_INDEX_DASHBOARD = 'authentic2.dashboard.CustomAppIndexDashboard'
ADMIN_TOOLS_MENU = 'authentic2.menu.CustomMenu'

AUTH_SAML2 = 'AUTH_SAML2' in os.environ
AUTH_OPENID = 'AUTH_OPENID' in os.environ
AUTH_SSL = 'AUTH_SSL' in os.environ
AUTH_OATH = 'AUTH_OATH' in os.environ
IDP_SAML2 = 'IDP_SAML2' in os.environ
IDP_OPENID = 'IDP_OPENID' in os.environ
IDP_CAS = 'IDP_CAS' in os.environ

try:
    from local_settings import *
except ImportError, e:
    if 'local_settings' in e.args[0]:
        pass

if USE_DEBUG_TOOLBAR:
    try:
        import debug_toolbar
        MIDDLEWARE_CLASSES += ('debug_toolbar.middleware.DebugToolbarMiddleware',)
        INSTALLED_APPS += ('debug_toolbar',)
    except ImportError:
        print "Debug toolbar missing, not loaded"

if AUTH_SAML2:
    INSTALLED_APPS += ('authentic2.authsaml2',)
    AUTHENTICATION_BACKENDS += (
            'authentic2.authsaml2.backends.AuthSAML2PersistentBackend',
            'authentic2.authsaml2.backends.AuthSAML2TransientBackend')
    AUTH_FRONTENDS += ('authentic2.authsaml2.frontend.AuthSAML2Frontend',)
    IDP_BACKENDS += ('authentic2.authsaml2.backends.AuthSAML2Backend',)
    DISPLAY_MESSAGE_ERROR_PAGE = True

if AUTH_OPENID:
    INSTALLED_APPS += ('authentic2.auth2_auth.auth2_openid', 'django_authopenid',)
    AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_openid.backend.OpenIDFrontend',)

if AUTH_SSL:
    AUTHENTICATION_BACKENDS += ('authentic2.auth2_auth.auth2_ssl.backend.SSLBackend',)
    AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_ssl.frontend.SSLFrontend',)
    INSTALLED_APPS += ('authentic2.auth2_auth.auth2_ssl',)

if AUTH_OATH:
    INSTALLED_APPS += ('authentic2.auth2_auth.auth2_oath',)
    AUTHENTICATION_BACKENDS += ('authentic2.auth2_auth.auth2_oath.backend.OATHTOTPBackend',)
    AUTH_FRONTENDS += ('authentic2.auth2_auth.auth2_oath.frontend.OATHOTPFrontend',)

if IDP_SAML2:
    IDP_BACKENDS += ('authentic2.idp.saml.backend.SamlBackend',)

if IDP_OPENID:
    INSTALLED_APPS += ('authentic2.idp.idp_openid',)
    TEMPLATE_CONTEXT_PROCESSORS += ('authentic2.idp.idp_openid.context_processors.openid_meta',)

if IDP_CAS:
    INSTALLED_APPS += ('authentic2.idp.idp_cas',)
