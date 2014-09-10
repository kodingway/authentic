from django.conf.urls import patterns, url, include
from django.conf import settings
from django.contrib import admin

from . import app_settings, plugins

admin.autodiscover()

handler500 = 'authentic2.views.server_error'

urlpatterns = patterns('authentic2.views', url(r'^$', 'homepage',
    name='auth_homepage'))

not_homepage_patterns = patterns('authentic2.views',
    url(r'^login/$', 'login', name='auth_login'),
    url(r'^logout/$', 'logout', name='auth_logout'),
    url(r'^redirect/(.*)', 'redirect', name='auth_redirect'),
    url(r'^accounts/', include('authentic2.profile_urls')),
)



not_homepage_patterns += patterns('',
    url(r'^accounts/', include(app_settings.A2_REGISTRATION_URLCONF)),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^admin_tools/', include('admin_tools.urls')),
    url(r'^idp/', include('authentic2.idp.urls')),
    url(r'^manage/', include('authentic2.manager.urls')),
)


urlpatterns += not_homepage_patterns

try:
    if getattr(settings, 'DISCO_SERVICE', False):
        urlpatterns += patterns('',
            (r'^disco_service/', include('disco_service.disco_responder')),
        )
except:
    pass

if settings.DEBUG:
    urlpatterns += patterns('django.contrib.staticfiles.views',
        url(r'^static/(?P<path>.*)$', 'serve'),
    )
 
if settings.USE_DEBUG_TOOLBAR:
    try:
        import debug_toolbar
        urlpatterns += patterns('',
            url(r'^__debug__/', include(debug_toolbar.urls)),
        )
    except ImportError:
        pass

urlpatterns = plugins.register_plugins_urls(urlpatterns)
