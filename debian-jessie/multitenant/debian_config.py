import os
from django.utils.translation import ugettext_lazy as _

# Debian defaults
DEBUG = False

PROJECT_NAME = 'authentic2-multitenant'

#
# hobotization (multitenant)
#
execfile('/usr/lib/hobo/debian_config_common.py')

# Add the XForwardedForMiddleware
MIDDLEWARE_CLASSES = ('authentic2.middleware.XForwardedForMiddleware',) + MIDDLEWARE_CLASSES

# Add authentic settings loader
TENANT_SETTINGS_LOADERS = ('hobo.multitenant.settings_loaders.Authentic',) + TENANT_SETTINGS_LOADERS

# Add authentic2 hobo agent
INSTALLED_APPS = ('hobo.agent.authentic2',) + INSTALLED_APPS

LOGGING['filters'].update({
    'cleaning': {
        '()':  'authentic2.utils.CleanLogMessage',
    },
})
for handler in LOGGING['handlers'].values():
    handler.setdefault('filters', []).append('cleaning')
# django_select2 outputs debug message at level INFO
LOGGING['loggers']['django_select2'] = {
    'handlers': ['syslog'],
    'level': 'WARNING',
}

# Default login's form username label
A2_USERNAME_LABEL = _('Email')

# Rest Authentication Class for services access
REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] += ('hobo.rest_authentication.PublikAuthentication',)
HOBO_ANONYMOUS_SERVICE_USER_CLASS = 'hobo.rest_authentication.AnonymousAuthenticServiceUser'

# HOBO Skeletons

HOBO_SKELETONS_DIR = os.path.join(VAR_DIR, 'skeletons')

CONFIG_FILE='/etc/%s/config.py' % PROJECT_NAME
if os.path.exists(CONFIG_FILE):
    execfile(CONFIG_FILE)
