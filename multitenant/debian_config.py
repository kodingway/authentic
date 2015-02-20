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
    'hobo.multitenant.middleware.TenantMiddleware',
    'hobo.middleware.settings.AuthenticSettingsMiddleware'
) + MIDDLEWARE_CLASSES

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

if os.path.exists(os.path.join(ETC_DIR, 'config.py')):
    execfile(os.path.join(ETC_DIR, 'config.py'))
