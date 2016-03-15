import os
import warnings


# Add the XForwardedForMiddleware
MIDDLEWARE_CLASSES = ('authentic2.middleware.XForwardedForMiddleware',) + MIDDLEWARE_CLASSES

# Debian defaults
DEBUG = False

STATIC_ROOT = '/var/lib/authentic2/collectstatic/'
STATICFILES_DIRS = ('/var/lib/authentic2/static',) + STATICFILES_DIRS
TEMPLATE_DIRS = ('/var/lib/authentic2/templates',) + TEMPLATE_DIRS
LOCALE_PATHS = ('/var/lib/authentic2/locale',) + LOCALE_PATHS

ADMINS = (('root', 'root@localhost'),)

if os.path.exists('/var/lib/authentic2/secret_key'):
    SECRET_KEY = file('/var/lib/authentic2/secret_key').read()

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
    },
    'formatters': {
        'syslog': {
            'format': '%(ip)s %(user)s %(request_id)s %(levelname)s %(name)s.%(funcName)s: %(message)s',
        },
    },
    'handlers': {
        'syslog': {
            'level': 'DEBUG',
            'address': '/dev/log',
            'class': 'logging.handlers.SysLogHandler',
            'filters': ['cleaning', 'request_context'],
            'formatter': 'syslog',
        },
    },
    'loggers': {
        # even when debugging seeing SQL queries is too much, activate it
        # explicitly using DEBUG_DB
        'django.db': {
                'handlers': ['syslog'],
                'level': 'INFO',
        },
        'django': {
                'level': 'INFO',
        },
        # django_select2 outputs debug message at level INFO
        'django_select2': {
                'handlers': ['syslog'],
                'level': 'WARNING',
        },
        '': {
                'handlers': ['syslog'],
                'level': 'INFO',
        },
    },
}

# Old settings method
def extract_settings_from_environ():
    import os
    import json
    from django.core.exceptions import ImproperlyConfigured
    global MANAGERS, DATABASES, SENTRY_TRANSPORT, SENTRY_DSN, INSTALLED_APPS, \
            SECURE_PROXY_SSL_HEADER, CACHES, SESSION_ENGINE, LDAP_AUTH_SETTINGS

    BOOLEAN_ENVS = (
           'DEBUG',
           'DEBUG_PROPAGATE_EXCEPTIONS',
           'SESSION_EXPIRE_AT_BROWSER_CLOSE',
           'SESSION_COOKIE_SECURE',
           'EMAIL_USE_TLS',
           'USE_X_FORWARDED_HOST',
           'DISCO_SERVICE',
           'DISCO_USE_OF_METADATA',
           'SHOW_DISCO_IN_MD',
           'SSLAUTH_CREATE_USER',
           'PUSH_PROFILE_UPDATES',
           'A2_ACCEPT_EMAIL_AUTHENTICATION',
           'A2_CAN_RESET_PASSWORD',
           'A2_REGISTRATION_CAN_DELETE_ACCOUNT',
           'A2_REGISTRATION_EMAIL_IS_UNIQUE',
           'REGISTRATION_OPEN',
           'A2_AUTH_PASSWORD_ENABLE',
           'SSLAUTH_ENABLE',
           'A2_IDP_SAML2_ENABLE',
           'IDP_OPENID',

    )

    def to_boolean(name, default=True):
        try:
            value = os.environ[name]
        except KeyError:
            return default
        try:
            i = int(value)
            return bool(i)
        except ValueError:
            if value.lower() in ('true', 't', 'y', 'yes'):
                return True
            if value.lower() in ('false', 'f', 'n', 'no'):
                return False
        return default

    for boolean_env in BOOLEAN_ENVS:
        if boolean_env in os.environ:
            globals()[boolean_env] = to_boolean(boolean_env)

    STRING_ENVS = (
        'STATIC_ROOT',
        'STATIC_URL',
        'A2_OPENED_SESSION_COOKIE_DOMAIN',
        'SESSION_COOKIE_NAME',
        'SESSION_COOKIE_PATH',
        'SESSION_ENGINE',
        'EMAIL_HOST',
        'EMAIL_HOST_USER',
        'EMAIL_HOST_PASSWORD',
        'EMAIL_SUBJECT_PREFIX',
        'SERVER_EMAIL',
        'DEFAULT_FROM_EMAIL',
        'LOGIN_REDIRECT_URL',
        'LOGIN_URL',
        'LOGOUT_URL',
        'SECRET_KEY',
        'DISCO_SERVICE_NAME',
        'SAML_SIGNATURE_PUBLIC_KEY',
        'SAML_SIGNATURE_PRIVATE_KEY',
        'SAML_METADATA_AUTOLOAD',
        'A2_HOMEPAGE_URL',
    )

    for string_env in STRING_ENVS:
        if string_env in os.environ:
            globals()[string_env] = os.environ[string_env]

    PATH_ENVS = (
        'STATICFILES_DIRS',
        'TEMPLATE_DIRS',
        'LOCALE_PATHS',
        'ALLOWED_HOSTS',
        'INTERNAL_IPS',
        'PASSWORD_HASHERS',
    )

    for path_env in PATH_ENVS:
        if path_env in os.environ:
            old = globals().get(path_env)
            globals()[path_env] = tuple(os.environ[path_env].split(':')) + tuple(old)

    INT_ENVS = (
            'SESSION_COOKIE_AGE',
            'EMAIL_PORT',
            'AUTHENTICATION_EVENT_EXPIRATION',
            'LOCAL_METADATA_CACHE_TIMEOUT',
            'ACCOUNT_ACTIVATION_DAYS',
            'PASSWORD_RESET_TIMEOUT_DAYS',
    )

    def to_int(name, default):
        try:
            value = os.environ[name]
            return int(value)
        except KeyError:
            return default
        except ValueError:
            raise ImproperlyConfigured('environ variable %s must be an integer' % name)

    for int_env in INT_ENVS:
        if int_env in os.environ:
            try:
                globals()[int_env] = int(os.environ[int_env])
            except ValueError:
                raise ImproperlyConfigured('environement variable %s must be an integer' % int_env)


    ADMINS = ()
    if 'ADMINS' in os.environ:
        ADMINS = filter(None, os.environ.get('ADMINS').split(':'))
        ADMINS = [ admin.split(';') for admin in ADMINS ]
        for admin in ADMINS:
            assert len(admin) == 2, 'ADMINS setting must be a colon separated list of name and emails separated by a semi-colon'
            assert '@' in admin[1], 'ADMINS setting pairs second value must be emails'
        MANAGERS = ADMINS


    for key in os.environ:
        if key.startswith('DATABASE_'):
            prefix, db_key = key.split('_', 1)
            DATABASES['default'][db_key] = os.environ[key]

    if 'SECURE_PROXY_SSL_HEADER' in os.environ:
        SECURE_PROXY_SSL_HEADER = os.environ['SECURE_PROXY_SSL_HEADER'].split(':', 1)

    if 'LDAP_AUTH_SETTINGS' in os.environ:
        try:
            LDAP_AUTH_SETTINGS = json.loads(os.environ['LDAP_AUTH_SETTINGS'])
        except Exception, e:
            raise ImproperlyConfigured('LDAP_AUTH_SETTINGS is not a JSON document', e)

    if 'CACHE_BACKEND' in os.environ:
        CACHES['default'] = json.loads(os.environ['CACHE_BACKEND'])

    if 'USE_MEMCACHED' in os.environ:
        try:
            import memcache
        except:
            raise ImproperlyConfigured('Python memcache library is not installed, please do: pip install memcache')
        CACHES = {
                'default': {
                    'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
                    'LOCATION': '127.0.0.1:11211',
                    'KEY_PREFIX': 'authentic2',
                    }
                }
        SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'

    # add sentry handler if environment contains SENTRY_DSN
    if 'SENTRY_DSN' in os.environ:
        try:
            from raven.transport.requests import RequestsHTTPTransport
        except ImportError:
            raise ImproperlyConfigured('unable to load python-raven')
        else:
            SENTRY_DSN = os.environ['SENTRY_DSN']
            SENTRY_TRANSPORT = RequestsHTTPTransport
            INSTALLED_APPS = tuple(INSTALLED_APPS) + ('raven.contrib.django.raven_compat',)
            LOGGING['handlers']['sentry'] = {
                'level': 'ERROR',
                'class': 'raven.contrib.django.raven_compat.handlers.SentryHandler'
            }
            LOGGING['loggers']['']['handlers'].append('sentry')


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

extract_settings_from_environ()

CONFIG_FILE = '/etc/authentic2/config.py'
if os.path.exists(CONFIG_FILE):
    execfile(CONFIG_FILE)

# Warn if DEFAULT_FROM_EMAIL is the default value
if DEFAULT_FROM_EMAIL == 'webmaster@localhost':
    warnings.warn('DEFAULT_FROM_EMAIL must be customized')
