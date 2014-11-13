from django.core.exceptions import ImproperlyConfigured

from ...decorators import to_list

AUTHORIZED_KEYS = set(('name', 'label', 'template'))

@to_list
def get_field_refs(format_string):
    '''
    Extract the base references from format_string
    '''
    from string import Formatter
    l = Formatter().parse(format_string)
    for p in l:
        field_ref = p[1].split('[', 1)[0]
        field_ref = field_ref.split('.', 1)[0]
    yield field_ref

UNEXPECTED_KEYS_ERROR = \
        '{0}: unexpected ' 'key(s) {1} in configuration'
FORMAT_STRING_ERROR = \
        '{0}: template string must contain only keyword references: {1}'
BAD_CONFIG_ERROR = \
        'template attribute source must contain a name and at least a template'
TYPE_ERROR = \
        'template attribute must be a string'

def config_error(fmt, *args):
    raise ImproperlyConfigured(fmt.format(__name__, *args))

@to_list
def get_instances(ctx):
    '''
    Retrieve instances from settings
    '''
    from django.conf import settings
    for kind, d in getattr(settings, 'ATTRIBUTE_SOURCES', []):
        if kind != 'template':
            continue
        keys = set(d.keys())
        if not keys <= AUTHORIZED_KEYS:
            unexpected = keys - AUTHORIZED_KEYS
            config_error(UNEXPECTED_KEYS_ERROR, unexpected)
        if 'name' not in keys or 'template' not in keys:
            config_error(BAD_CONFIG_ERROR)
        if not isinstance(d['template'], basestring):
            config_error(TYPE_ERROR)
        yield d


def get_attribute_names(instance, ctx):
    name = instance['name']
    return ((name, instance.get('label', name)),)

def get_dependencies(instance, ctx):
    return get_field_refs(instance['template'])

def get_attributes(instance, ctx):
    return {instance['name']: instance['template'].format(**ctx)}
