'''Package to hold default settings for authentic2'''

import os


from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


__sentinel = object()


def setting(names, default=__sentinel, definition=''):
    '''Try to retrieve a setting whose name is among names,
       if not return default, if default is not set raise
       an ImproperlyConfigured exception.
    '''
    if isinstance(names, basestring):
        names = (names,)
    for name in names:
        result = getattr(settings, name, __sentinel)
        if result is not __sentinel:
            return result
    if default is __sentinel:
        if definition:
            definition = ' (%s)' % definition
        msg = 'Missing '\
                'setting%(definition)s: %(names)s' % {
                        'definition': definition,
                        'names': ', '.join(names) }
        raise ImproperlyConfigured(msg)
    return default

# SSL Certificate verification settings
CAFILE = setting(('AUTHENTIC2_CAFILE', 'CAFILE'),
        default='/etc/ssl/certs/ca-certificates.crt',
        definition='File containing certificate chains as PEM certificates')
CAPATH = setting(('AUTHENTIC2_CAPATH', 'CAPATH'), default='/etc/ssl/certs/',
        definition='Directory containing PEM certificates named'
        ' using OpenSSL certificate directory convention. '
        'See http://www.openssl.org/docs/apps/verify.html#item__CApath')


class Setting(object):
    __SENTINEL = object()

    def __init__(self, default=__SENTINEL, definition='', names=None):
        self.names = names or []
        if isinstance(self.names, basestring):
            self.names = [self.names]
        self.names = set(self.names)
        self.default = default
        self.definition = definition

    def get(self):
        for name in self.names:
            result = getattr(settings, name, self.__SENTINEL)
            if result is not self.__SENTINEL:
                return result
        for name in self.names:
            key = name
            if  key in os.environ:
                return os.environ[key]
        if self.default is self.__SENTINEL:
            if self.definition:
                self.definition = ' (%s)' % self.definition
            msg = 'Missing '\
                    'setting%(definition)s: %(names)s' % {
                            'definition': self.definition,
                            'names': ', '.join(self.names) }
            raise ImproperlyConfigured(msg)
        return self.default



# Registration
__settings = dict(
    A2_REGISTRATION_AUTHORIZED = Setting(default=True, definition='Allow online registration of users'),
    A2_REGISTRATION_URLCONF = Setting(default='authentic2.registration_backend.urls',
                definition='Root urlconf for the /accounts endpoints'),
    A2_REGISTRATION_FORM_CLASS = Setting(default='authentic2.registration_backend.forms.RegistrationForm',
                definition='Default registration form'),
    A2_REGISTRATION_CAN_DELETE_ACCOUNT = Setting(default=True,
                definition='Can user self delete their account and all their data')
)

for key, value in __settings.iteritems():
    value.names.add(key)
    globals()[key] = value.get()
