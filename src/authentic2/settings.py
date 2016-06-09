import logging
import logging.config
# Load default from Django
from django.conf.global_settings import *
import os

import django

from . import plugins, logger

BASE_DIR = os.path.dirname(__file__)
### Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/dev/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'please-change-me-with-a-very-long-random-string'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False
DEBUG_DB = False
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
USE_TZ = True

# Static files

STATIC_URL = '/static/'

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django_rbac.context_processors.auth',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.request',
    'django.contrib.messages.context_processors.messages',
    'django.core.context_processors.static',
    'authentic2.context_processors.a2_processor',
)

MIDDLEWARE_CLASSES = (
    'authentic2.middleware.StoreRequestMiddleware',
    'authentic2.middleware.RequestIdMiddleware',
    'authentic2.middleware.LoggingCollectorMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.http.ConditionalGetMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

DATABASES['default']['ATOMIC_REQUESTS'] = True

MIDDLEWARE_CLASSES += (
    'authentic2.middleware.DisplayMessageBeforeRedirectMiddleware',
    'authentic2.idp.middleware.DebugMiddleware',
    'authentic2.middleware.CollectIPMiddleware',
    'authentic2.middleware.ViewRestrictionMiddleware',
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
    'django.contrib.contenttypes',
    'authentic2.custom_user',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
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
    'authentic2_provisionning_ldap',
    'authentic2',
    'django_rbac',
    'authentic2.a2_rbac',
    'gadjo',
    'rest_framework',
)

INSTALLED_APPS = tuple(plugins.register_plugins_installed_apps(INSTALLED_APPS))

# authentication
AUTHENTICATION_BACKENDS = (
    'authentic2.backends.ldap_backend.LDAPBackend',
    'authentic2.backends.ldap_backend.LDAPBackendPasswordLost',
    'authentic2.backends.models_backend.ModelBackend',
    'authentic2.backends.models_backend.DummyModelBackend',
    'django_rbac.backends.DjangoRBACBackend',
)
AUTHENTICATION_BACKENDS = plugins.register_plugins_authentication_backends(
        AUTHENTICATION_BACKENDS)
CSRF_FAILURE_VIEW = 'authentic2.views.csrf_failure_view'


LOGIN_REDIRECT_URL = '/'
LOGIN_URL = '/login/'
LOGOUT_URL = '/logout/'

# Registration
ACCOUNT_ACTIVATION_DAYS = 2

# Authentic2 settings

###########################
# Authentication settings
###########################
AUTH_USER_MODEL = 'custom_user.User'
AUTH_FRONTENDS = plugins.register_plugins_auth_frontends((
    'authentic2.auth_frontends.LoginPasswordBackend',))

###########################
# RBAC settings
###########################
RBAC_OU_MODEL = 'a2_rbac.OrganizationalUnit'
RBAC_PERMISSION_MODEL = 'a2_rbac.Permission'
RBAC_ROLE_MODEL = 'a2_rbac.Role'
RBAC_ROLE_PARENTING_MODEL = 'a2_rbac.RoleParenting'

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

# Serialization module to support natural keys in generic foreign keys
SERIALIZATION_MODULES = {
        'json': 'authentic2.serializers',
}

LOGGING_CONFIG = None
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'filters': {
        'cleaning': {
            '()':  'authentic2.utils.CleanLogMessage',
        },
        'request_context': {
            '()':  'authentic2.log_filters.RequestContextFilter',
        },
        'force_debug': {
            '()': 'authentic2.log_filters.ForceDebugFilter',
        }
    },
    'formatters': {
        'verbose': {
            'format': '[%(asctime)s] %(ip)s %(user)s %(request_id)s %(levelname)s %(name)s.%(funcName)s: %(message)s',
            'datefmt': '%Y-%m-%d %a %H:%M:%S'
        },
        'verbose_db': {
            'format': '[%(asctime)s] - - - %(levelname)s %(name)s.%(funcName)s: %(message)s',
            'datefmt': '%Y-%m-%d %a %H:%M:%S'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'verbose',
            'filters': ['cleaning', 'request_context'],
        },
	# remove request_context filter for db log to prevent infinite loop
	# when logging sql query to retrieve the session user
        'console_db': {
            'level': 'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'verbose_db',
            'filters': ['cleaning'],
        },
    },
    'loggers': {
        # even when debugging seeing SQL queries is too much, activate it
        # explicitly using DEBUG_DB
        'django.db': {
                'handlers': ['console_db'],
                'level': logger.SettingsLogLevel('INFO', debug_setting='DEBUG_DB'),
                'propagate': False,
        },
        'django': {
                'level': 'INFO',
        },
        # django_select2 outputs debug message at level INFO
        'django_select2': {
                'level': 'WARNING',
        },
        # lasso has the bad habit of logging everything as errors
        'lasso': {
            'filters': ['force_debug'],
        },
        '': {
                'handlers': ['console'],
                'level': logger.SettingsLogLevel('INFO'),
        },
    },
}

MIGRATION_MODULES = {
        'auth': 'authentic2.auth_migrations',
        'menu': 'authentic2.menu_migrations',
        'dashboard': 'authentic2.dashboard_migrations',
}
if django.VERSION >= (1,8):
    MIGRATION_MODULES['auth'] = 'authentic2.auth_migrations_18'

# Django REST Framework
REST_FRAMEWORK = {
    'NON_FIELD_ERRORS_KEY': '__all__',
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'rest_framework.filters.DjangoFilterBackend',
        'rest_framework.filters.OrderingFilter',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 10,
}


# Authentic2 Auth SAML
MELLON_ADAPTER = ('authentic2_auth_saml.adapters.AuthenticAdapter',)


#
# Load configuration file
#

if 'AUTHENTIC2_SETTINGS_FILE' in os.environ:
    execfile(os.environ['AUTHENTIC2_SETTINGS_FILE'])
logging.config.dictConfig(LOGGING)
