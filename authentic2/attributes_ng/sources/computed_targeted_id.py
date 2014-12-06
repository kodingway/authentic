'''
Compute a targeted id based on a hash of existing attributes, to compute a
targetd id for a service provider and a user coming from an LDAP store using
the interOrgPerson objectClass you can use the following
configuration:

    ('computed_targeted_id', {
        'name': u'uid_targeted_id',
        'label' u'Targeted id based on the uid and the service audience',
        'source_attributes': ['service', 'uid'],
        'salt': 'oijpoewkrpowekrpeowkr',
     })
'''

import hashlib
import base64

from django.core.exceptions import ImproperlyConfigured

from ...decorators import to_list

AUTHORIZED_KEYS = set(('name', 'label', 'source_attributes', 'salt', 'hash'))

REQUIRED_KEYS = set(('name', 'source_attributes', 'salt'))

UNEXPECTED_KEYS_ERROR = \
        '{0}: unexpected key(s) {1} in configuration'
MISSING_KEYS_ERROR = \
        '{0}: missing key(s) {1} in configuration'
BAD_CONFIG_ERROR = \
        '{0}: template attribute source must contain a name, a list of dependencies and a function'
NOT_CALLABLE_ERROR = \
        '{0}: function attribute must be callable'
SOURCE_ATTRIBUTE_TYPE_ERROR = '{0}: source_attributes must be a list of string'

def config_error(fmt, *args):
    raise ImproperlyConfigured(fmt.format(__name__, *args))

@to_list
def get_instances(ctx):
    '''
    Retrieve instances from settings
    '''
    from django.conf import settings
    for kind, d in getattr(settings, 'ATTRIBUTE_SOURCES', []):
        if kind != 'computed_targeted_id':
            continue
        keys = set(d.keys())
        if not keys <= AUTHORIZED_KEYS:
            unexpected = keys - AUTHORIZED_KEYS
            config_error(UNEXPECTED_KEYS_ERROR, unexpected)
        if not REQUIRED_KEYS <= keys:
            missing = REQUIRED_KEYS - keys
            config_error(MISSING_KEYS_ERROR, missing)
        dependencies = d['source_attributes']
        if not isinstance(dependencies, (list, tuple)) or \
                not all(map(lambda x: isinstance(x, str), dependencies)):
            config_error(SOURCE_ATTRIBUTE_TYPE_ERROR)
        yield d


def get_attribute_names(instance, ctx):
    name = instance['name']
    return ((name, instance.get('label', name)),)

def get_dependencies(instance, ctx):
    return instance['source_attributes']

def get_attributes(instance, ctx):
    source_attributes = instance['source_attributes']
    source_attributes_values = []
    for source_attribute in source_attributes:
        if source_attribute not in ctx:
            return {}
        value = ctx[source_attribute]
        if isinstance(value, (list, tuple)):
            values = value
            for value in values:
                source_attributes_values.append(value)
    source_attributes_values.append(instance['salt'])
    hash_algo = instance.get('hash', 'sha1')
    hasher = getattr(hashlib, hash_algo)
    source_attributes_values = map(unicode, source_attributes_values)
    value = u'!'.join(source_attributes_values)
    value = value.encode('utf-8')
    value = hasher(value).digest()
    value = base64.b64encode(value)
    return {instance['name']: value}
