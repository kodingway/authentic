from django.contrib.auth.decorators import login_required
from django.conf.urls import patterns, url, include
from django.conf import settings

from authentic2.idp.decorators import prevent_access_to_transient_users

import authentic2.idp.views

from .admin import admin
from . import app_settings

admin.autodiscover()
handler500 = 'authentic2.views.server_error'


if app_settings.A2_HOMEPAGE_URL:
    urlpatterns = patterns('authentic2.views',
        url(r'^$', 'redirect_to_homepage'))
else:
    urlpatterns = patterns('',
        url(r'^$', login_required(authentic2.idp.views.homepage), name='index'))

not_homepage_patterns = patterns('',
    url(r'^', include('authentic2.auth2_auth.urls')),
    url(r'^redirect/(.*)', 'authentic2.views.redirect'),
    url(r'^accounts/', include(app_settings.A2_REGISTRATION_URLCONF)),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^admin_tools/', include('admin_tools.urls')),
    url(r'^idp/', include('authentic2.idp.urls')),
    url(r'^logout/$', 'authentic2.idp.views.logout', name='auth_logout'),
    url(r'^profile/edit/$', 'authentic2.views.edit_profile',
        name='profile_edit'),
    url(r'^profile/change-email/$', 'authentic2.views.email_change',
        name='email-change'),
    url(r'^profile/change-email/verify/$', 'authentic2.views.email_change_verify',
        name='email-change-verify'),
    url(r'^profile/$',
        prevent_access_to_transient_users(authentic2.idp.views.profile), {},
        'account_management'),
)

if getattr(settings, 'IDP_OPENID', False):
    not_homepage_patterns += patterns('',
            (r'^openid/', include('authentic2.idp.idp_openid.urls')))

urlpatterns += not_homepage_patterns

urlpatterns += patterns('',
    (r'^authsaml2/', include('authentic2.authsaml2.urls')),
)

try:
    if settings.DISCO_SERVICE:
        urlpatterns += patterns('',
            (r'^disco_service/', include('disco_service.disco_responder')),
        )
except:
    pass
