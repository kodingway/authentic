import logging

from django.core.exceptions import ImproperlyConfigured

from ..decorators import to_list
from .. import app_settings, plugins, utils

__ALL__ = ['get_attribute_names', 'get_attributes']

class UnsortableError(Exception):
    '''
    Raise when topological_sort is unable to sort instance topologically.
    sorted_list contains the instances that could be sorted unsorted contains
    the instances that couldn't.
    '''
    def __init__(self, sorted_list, unsortable_instances):
        self.sorted_list = sorted_list
        self.unsortable_instances = unsortable_instances

    def __str__(self):
        return 'UnsortableError: %r' % self.unsortable_instances

def topological_sort(source_and_instances, ctx, raise_on_unsortable=False):
    '''
    Sort instances topologically based on their dependency declarations.
    '''
    sorted_list = []
    variables = set(ctx.keys())
    unsorted = list(source_and_instances)
    while True:
        count_sorted = len(sorted_list)
        new_unsorted = []
        for source, instance in unsorted:
            dependencies = set(source.get_dependencies(instance, ctx))
            if dependencies <= variables:
                sorted_list.append((source, instance))
                variables.update(a for a, b in source.get_attribute_names(instance, ctx))
            else:
                new_unsorted.append((source, instance))
        unsorted = new_unsorted
        if len(sorted_list) == len(source_and_instances): # finished !
            break
        elif count_sorted == len(sorted_list): # no progress !
            if raise_on_unsortable:
                raise UnsortableError(sorted_list, unsorted)
            else:
                logger = logging.getLogger(__name__)
                for source, instance in unsorted:
                    dependencies = set(source.get_dependencies(instance, ctx))
                    sorted_list.append((source, instance))
                    logger.error('missing dependencies for instance %r of %r: %s',
                            instance, source,
                            list(dependencies-variables))
                break
    return sorted_list

@to_list
def get_sources():
    '''
    List all known sources
    '''
    for path in app_settings.ATTRIBUTE_BACKENDS:
        yield utils.import_module_or_class(path)
    for plugin in plugins.get_plugins():
        if hasattr(plugin, 'get_attribute_backends'):
            for path in plugin.get_attribute_backends():
                yield utils.import_module_or_class(path)

@to_list
def get_attribute_names(ctx):
    '''
    Return attribute names from all sources
    '''
    for source in get_sources():
        for instance in source.get_instances(ctx):
            for attribute_name, attribute_description in source.get_attribute_names(instance, ctx):
                yield attribute_name, attribute_description


def get_attributes(ctx):
    '''
    Traverse and sources instances and aggregate produced attributes.

    Traversal is done by respecting a topological sort of instances based on
    their declared dependencies
    '''
    source_and_instances = []
    for source in get_sources():
        source_and_instances.extend(((source, instance) for instance in
            source.get_instances(ctx)))
    source_and_instances = topological_sort(source_and_instances, ctx)
    ctx = ctx.copy()
    for source, instance in source_and_instances:
        ctx.update(source.get_attributes(instance, ctx.copy()))
    return ctx
