import logging

from django.apps import apps

from . import decorators


@decorators.GlobalCache
def get_hooks(hook_name):
    '''Return a list of defined hook named a2_hook<hook_name> on AppConfig classes of installed
       Django applications.

       Ordering of hooks can be defined using an orer field on the hook method.
    '''
    hooks = []
    for app in apps.get_app_configs():
        name = 'a2_hook_' + hook_name
        if hasattr(app, name):
            hooks.append(getattr(app, name))
    hooks.sort(key=lambda hook: getattr(hook, 'order', 0))
    return hooks


@decorators.to_list
def call_hooks(hook_name, *args, **kwargs):
    '''Call each a2_hook_<hook_name> and return the list of results.'''
    logger = logging.getLogger(__name__)
    hooks = get_hooks(hook_name)
    for hook in hooks:
        try:
            yield hook(*args, **kwargs)
        except:
            logger.exception(u'exception while calling hook %s', hook)


def call_hooks_first_result(hook_name, *args, **kwargs):
    '''Call each a2_hook_<hook_name> and return the first not None result.'''
    logger = logging.getLogger(__name__)
    hooks = get_hooks(hook_name)
    for hook in hooks:
        try:
            result = hook(*args, **kwargs)
            if result is not None:
                return result
        except:
            logger.exception(u'exception while calling hook %s', hook)
