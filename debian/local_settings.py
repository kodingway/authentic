DEBUG = False

# traceback recipients if DEBUG=False
ADMINS = (
#    ('root', 'root@localhost'),
#    ('admin authentic', 'admin-authentic@domaine.com'),
)
MANAGERS = ADMINS

SECRET_KEY = 'coin'

# we're behind a pile of reverse-proxies...
# https://docs.djangoproject.com/en/dev/ref/settings/#allowed-hosts
ALLOWED_HOSTS = ['*']

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'Europe/Paris'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'fr-fr'

#
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/var/lib/passerelle/passerelle.db',
    }
}

MEDIA_ROOT = '/var/lib/passerelle/media'
MEDIA_URL = '/passerelle/media/'

STATIC_ROOT = '/usr/share/passerelle/static'
STATIC_URL = '/passerelle/static/'
