from django.core.exceptions import ImproperlyConfigured

from ...decorators import to_list

AUTHORIZED_KEYS = set(('name', 'label', 'dependencies', 'function'))

REQUIRED_KEYS = set(('name', 'dependencies', 'function'))

UNEXPECTED_KEYS_ERROR = \
        '{0}: unexpected key(s) {1} in configuration'
MISSING_KEYS_ERROR = \
        '{0}: missing key(s) {1} in configuration'
BAD_CONFIG_ERROR = \
        '{0}: template attribute source must contain a name, a list of dependencies and a function'
NOT_CALLABLE_ERROR = \
        '{0}: function attribute must be callable'
DEPENDENCY_TYPE_ERROR = '{0}: dependencies must be a list of string'

def config_error(fmt, *args):
    raise ImproperlyConfigured(fmt.format(__name__, *args))

@to_list
def get_instances(ctx):
    '''
    Retrieve instances from settings
    '''
    from django.conf import settings
    for kind, d in getattr(settings, 'ATTRIBUTE_SOURCES', []):
        if kind != 'function':
            continue
        keys = set(d.keys())
        if not keys <= AUTHORIZED_KEYS:
            unexpected = keys - AUTHORIZED_KEYS
            config_error(UNEXPECTED_KEYS_ERROR, unexpected)
        if not REQUIRED_KEYS <= keys:
            missing = REQUIRED_KEYS - keys
            config_error(MISSING_KEYS_ERROR, missing)
        dependencies = d['dependencies']
        if not isinstance(dependencies, (list, tuple)) or \
                not all(map(lambda x: isinstance(x, str), dependencies)):
            config_error(DEPENDENCY_TYPE_ERROR)


        if not callable(d['function']):
            config_error(NOT_CALLABLE_ERROR)
        yield d


def get_attribute_names(instance, ctx):
    name = instance['name']
    return ((name, instance.get('label', name)),)

def get_dependencies(instance, ctx):
    return instance.get('dependencies', ())

def get_attributes(instance, ctx):
    args = instance.get('args', ())
    kwargs = instance.get('kwargs', {})
    value = instance['function'](ctx, *args, **kwargs)
    return {instance['name']: value}
