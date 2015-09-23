import os

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
    'request_context': {
        '()':  'authentic2.log_filters.RequestContextFilter',
    },
})
LOGGING['formatters']['syslog'] = {
    'format': '%(ip)s %(user)s %(request_id)s %(levelname)s %(name)s.%(funcName)s: %(message)s'
}
LOGGING['handlers']['syslog']['filters'] = ['cleaning', 'request_context']
# django_select2 outputs debug message at level INFO
LOGGING['loggers']['django_select2'] = {
    'handlers': ['syslog'],
    'level': 'WARNING',
}

CONFIG_FILE='/etc/%s/config.py' % PROJECT_NAME
if os.path.exists(CONFIG_FILE):
    execfile(CONFIG_FILE)
