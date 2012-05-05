'''Package to hold default settings for authentic2'''

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
