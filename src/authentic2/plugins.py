"""
    Use setuptools entrypoints to find plugins

    Propose helper methods to load urls from plugins or modify INSTALLED_APPS
"""
import pkg_resources
import logging


from django.conf.urls import patterns, include, url


logger = logging.getLogger(__name__)


__ALL__ = ['get_plugins']

PLUGIN_CACHE = {}

class PluginError(Exception):
    pass

DEFAULT_GROUP_NAME = 'authentic2.plugin'

def get_plugins(group_name=DEFAULT_GROUP_NAME, use_cache=True, *args, **kwargs):
    '''Traverse all entry points for group_name and instantiate them using args
       and kwargs.
    '''
    global PLUGIN_CACHE
    if group_name in PLUGIN_CACHE and use_cache:
        return PLUGIN_CACHE[group_name]
    plugins = []
    for entrypoint in pkg_resources.iter_entry_points(group_name):
        try:
            plugin_callable = entrypoint.load()
        except Exception, e:
            raise
            logger.exception('unable to load entrypoint %s', entrypoint)
            raise PluginError('unable to load entrypoint %s' % entrypoint, e)
        plugins.append(plugin_callable(*args, **kwargs))
    PLUGIN_CACHE[group_name] = plugins
    return plugins

def register_plugins_urls(urlpatterns,
        group_name=DEFAULT_GROUP_NAME):
    '''Call get_before_urls and get_after_urls on all plugins providing them
       and add those urls to the given urlpatterns.

       URLs returned by get_before_urls() are added to the head of urlpatterns
       and those returned by get_after_urls() are added to the tail of
       urlpatterns.
    '''
    plugins = get_plugins(group_name)
    before_urls = []
    after_urls = []
    for plugin in plugins:
        if hasattr(plugin, 'get_before_urls'):
            urls = plugin.get_before_urls()
            before_urls.append(url('^', include(urls)))
        if hasattr(plugin, 'get_after_urls'):
            urls = plugin.get_after_urls()
            after_urls.append(url('^', include(urls)))
    before_patterns = patterns('', *before_urls)
    after_patterns = patterns('', *after_urls)
    return before_patterns + urlpatterns + after_patterns

def register_plugins_installed_apps(installed_apps, group_name=DEFAULT_GROUP_NAME):
    '''Call get_apps() on all plugins of group_name and add the returned
       applications path to the installed_apps sequence. 

       Applications already present are ignored.
    '''
    installed_apps = list(installed_apps)
    for plugin in get_plugins(group_name):
        if hasattr(plugin, 'get_apps'):
            apps = plugin.get_apps()
            for app in apps:
                if app not in installed_apps:
                    installed_apps.append(app)
    return installed_apps

def register_plugins_middleware(middleware_classes,
        group_name=DEFAULT_GROUP_NAME):
    middleware_classes = list(middleware_classes)
    for plugin in get_plugins(group_name):
        if hasattr(plugin, 'get_before_middleware'):
            apps = plugin.get_before_middleware()
            for app in reversed(apps):
                if app not in middleware_classes:
                    middleware_classes.insert(0, app)
        if hasattr(plugin, 'get_after_middleware'):
            apps = plugin.get_after_middleware()
            for app in apps:
                if app not in middleware_classes:
                    middleware_classes.append(app)
    return tuple(middleware_classes)

def register_plugins_authentication_backends(authentication_backends,
        group_name=DEFAULT_GROUP_NAME):
    authentication_backends = list(authentication_backends)
    for plugin in get_plugins(group_name):
        if hasattr(plugin, 'get_authentication_backends'):
            cls = plugin.get_authentication_backends()
            for cls in cls:
                if cls not in authentication_backends:
                    authentication_backends.append(cls)
    return tuple(authentication_backends)

def register_plugins_auth_frontends(auth_frontends=(),
        group_name=DEFAULT_GROUP_NAME):
    auth_frontends = list(auth_frontends)
    for plugin in get_plugins(group_name):
        if hasattr(plugin, 'get_auth_frontends'):
            cls = plugin.get_auth_frontends()
            for cls in cls:
                if cls not in auth_frontends:
                    auth_frontends.append(cls)
    return tuple(auth_frontends)

def register_plugins_idp_backends(idp_backends,
        group_name=DEFAULT_GROUP_NAME):
    idp_backends = list(idp_backends)
    for plugin in get_plugins(group_name):
        if hasattr(plugin, 'get_idp_backends'):
            cls = plugin.get_idp_backends()
            for cls in cls:
                if cls not in idp_backends:
                    idp_backends.append(cls)
    return tuple(idp_backends)

def init():
    for plugin in get_plugins():
        if hasattr(plugin, 'init'):
            plugin.init()
