# Load default from Django
from django.conf.global_settings import *
import os

import django

from . import plugins

BASE_DIR = os.path.dirname(__file__)

### Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/dev/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'please-change-me-with-a-very-long-random-string'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
TEMPLATE_DEBUG = True
MEDIA = 'media'

# See https://docs.djangoproject.com/en/dev/ref/settings/#allowed-hosts
ALLOWED_HOSTS = []

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'authentic2.sqlite3',
    }
}

### End of "Quick-start development settings"


# Hey Entr'ouvert is in France !!
TIME_ZONE = 'Europe/Paris'
LANGUAGE_CODE = 'fr'
USE_L10N = True

# Static files

STATIC_URL = '/static/'

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.request',
    'django.contrib.messages.context_processors.messages',
    'django.core.context_processors.static',
    'authentic2.context_processors.a2_processor',
    'sekizai.context_processors.sekizai',
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
)

if django.VERSION < (1, 6, 0):
    MIDDLEWARE_CLASSES += (
        'django.middleware.transaction.TransactionMiddleware',
    )

MIDDLEWARE_CLASSES += (
    'authentic2.idp.middleware.DebugMiddleware',
    'authentic2.middleware.CollectIPMiddleware',
    'authentic2.middleware.StoreRequestMiddleware',
    'authentic2.middleware.ViewRestrictionMiddleware',
)

A2_OPENED_SESSION_COOKIE_DOMAIN = os.environ.get('A2_OPENED_SESSION_COOKIE_DOMAIN')
if A2_OPENED_SESSION_COOKIE_DOMAIN:
    MIDDLEWARE_CLASSES += (
        'authentic2.middleware.OpenedSessionCookieMiddleware',
    )

MIDDLEWARE_CLASSES = plugins.register_plugins_middleware(MIDDLEWARE_CLASSES)

ROOT_URLCONF = 'authentic2.urls'

TEMPLATE_DIRS = (os.path.join(BASE_DIR, 'templates'),)

STATICFILES_DIRS = (os.path.join(BASE_DIR, 'static'),)

STATICFILES_FINDERS = STATICFILES_FINDERS + ('gadjo.finders.XStaticFinder',)

LOCALE_PATHS = ( os.path.join(BASE_DIR, 'locale'), )

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
    'django_select2',
    'django_tables2',
    'authentic2.nonce',
    'authentic2.saml',
    'authentic2.idp',
    'authentic2.idp.saml',
    'authentic2.auth2_auth',
    'authentic2.attribute_aggregator',
    'authentic2.disco_service',
    'authentic2.manager',
    'authentic2',
    'gadjo',
    'sekizai',
)

INSTALLED_APPS = tuple(plugins.register_plugins_installed_apps(INSTALLED_APPS))

# authentication
AUTHENTICATION_BACKENDS = (
    'authentic2.backends.ldap_backend.LDAPBackend',
    'authentic2.backends.ldap_backend.LDAPBackendPasswordLost',
    'authentic2.backends.models_backend.ModelBackend',
)
AUTHENTICATION_BACKENDS = plugins.register_plugins_authentication_backends(
        AUTHENTICATION_BACKENDS)

LOGIN_REDIRECT_URL = '/'
LOGIN_URL = '/login/'
LOGOUT_URL = '/logout/'

# Registration
ACCOUNT_ACTIVATION_DAYS = 2

# Authentic2 settings

###########################
# Authentication settings
###########################

AUTH_FRONTENDS = plugins.register_plugins_auth_frontends((
    'authentic2.auth_frontends.LoginPasswordBackend',))

#############################
# Identity Provider settings
#############################

# List of IdP backends, mainly used to show available services in the homepage
# of user, and to handle SLO for each protocols
IDP_BACKENDS = plugins.register_plugins_idp_backends(())

# Whether to autoload SAML 2.0 identity providers and services metadata
# Only https URLS are accepted.
# Can be none, sp, idp or both

PASSWORD_HASHERS += (
        'authentic2.hashers.Drupal7PasswordHasher',
        'authentic2.hashers.SHA256PasswordHasher',
        'authentic2.hashers.SSHA1PasswordHasher',
        'authentic2.hashers.SMD5PasswordHasher',
        'authentic2.hashers.SHA1OLDAPPasswordHasher',
        'authentic2.hashers.MD5OLDAPPasswordHasher',
)

# Admin tools
ADMIN_TOOLS_INDEX_DASHBOARD = 'authentic2.dashboard.CustomIndexDashboard'
ADMIN_TOOLS_APP_INDEX_DASHBOARD = 'authentic2.dashboard.CustomAppIndexDashboard'
ADMIN_TOOLS_MENU = 'authentic2.menu.CustomMenu'

# Remove after Django 1.7
SERIALIZATION_MODULES = {
        'json': 'authentic2.serializers',
}

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
            'format': '[%(asctime)s] %(levelname)s %(name)s.%(funcName)s: %(message)s',
            'datefmt': '%Y-%m-%d %a %H:%M:%S'
        },
        'syslog': {
            'format': '%(levelname)s %(name)s.%(funcName)s: %(message)s',
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
        'lasso': {
                'handlers': ['mail_admins', 'syslog'],
                'level': 'WARNING',
                'propagate': False,
        },
        '': {
                'handlers': ['mail_admins', 'syslog'],
                'level': 'WARNING',
        },
    },
}

#
# Load configuration file
#

if 'AUTHENTIC2_SETTINGS_FILE' in os.environ:
    execfile(os.environ['AUTHENTIC2_SETTINGS_FILE'])

#
# Apply monkey patches
#

from . import fix_user_model
