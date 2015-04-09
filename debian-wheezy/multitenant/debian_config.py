import os

from django.core.exceptions import ImproperlyConfigured

PROJECT_NAME = 'authentic2-multitenant'

try:
    import hobo
except ImportError:
    raise ImproperlyConfigured('hobo MUST be installed for the multitenant mode to work')

VAR_DIR = os.path.join('/var/lib', PROJECT_NAME)
ETC_DIR = os.path.join('/etc', PROJECT_NAME)

STATIC_ROOT = os.path.join(VAR_DIR, 'collected-static')
STATICFILES_DIRS = (os.path.join(VAR_DIR, 'static'),) + STATICFILES_DIRS
TEMPLATE_DIRS = (os.path.join(VAR_DIR, 'templates'),) + TEMPLATE_DIRS
LOCALE_PATHS = (os.path.join(VAR_DIR, 'locale'),) + LOCALE_PATHS

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
TEMPLATE_DEBUG = False

TENANT_MODEL = 'multitenant.Tenant'
TENANT_BASE = os.path.join(VAR_DIR, 'tenants')
TENANT_TEMPLATE_DIRS = (TENANT_BASE,)

SHARED_APPS = (
    'hobo.multitenant',
    'django.contrib.staticfiles',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
)

TENANT_APPS = INSTALLED_APPS

INSTALLED_APPS = ('hobo.multitenant', 'hobo.agent.authentic2') + INSTALLED_APPS

TEMPLATE_LOADERS = ('hobo.multitenant.template_loader.FilesystemLoader',) + TEMPLATE_LOADERS

TEMPLATE_CONTEXT_PROCESSORS = ('django.core.context_processors.request',) + TEMPLATE_CONTEXT_PROCESSORS

MIDDLEWARE_CLASSES = (
    'authentic2.middleware.XForwardedForMiddleware',
    'hobo.multitenant.middleware.TenantMiddleware',
    'hobo.multitenant.middleware.TenantSettingsMiddleware',
) + MIDDLEWARE_CLASSES

TENANT_SETTINGS_MIDDLEWARE_LOADERS = (
    'hobo.multitenant.settings_loaders.TemplateVars',
    'hobo.multitenant.settings_loaders.Authentic',
)

DEFAULT_FILE_STORAGE = 'hobo.multitenant.storage.TenantFileSystemStorage'

DATABASES = {
    'default': {
        'ENGINE': 'tenant_schemas.postgresql_backend',
        'NAME': PROJECT_NAME.replace('-', '_')
    }
}

DATABASE_ROUTERS = (
    'tenant_schemas.routers.TenantSyncRouter',
)

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

if os.path.exists(os.path.join(ETC_DIR, 'config.py')):
    execfile(os.path.join(ETC_DIR, 'config.py'))
