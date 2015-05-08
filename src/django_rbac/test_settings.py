from django.conf import global_settings

MIDDLEWARE_CLASSES = global_settings.MIDDLEWARE_CLASSES

SECRET_KEY='whatever'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'authentic2.sqlite3',
    }
}

INSTALLED_APPS = (
	'django.contrib.auth',
        'django.contrib.contenttypes',
        'django_rbac',
)

import os

if 'AUTHENTIC2_SETTINGS_FILE' in os.environ:
    execfile(os.environ['AUTHENTIC2_SETTINGS_FILE'])
