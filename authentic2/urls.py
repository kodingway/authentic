from django.contrib.auth.decorators import login_required
from django.conf.urls import patterns, url, include
from django.conf import settings

from authentic2.idp.decorators import prevent_access_to_transient_users

import authentic2.idp.views
from forms import AuthenticRegistrationForm

from .admin import admin

admin.autodiscover()
handler500 = 'authentic2.views.server_error'


urlpatterns = patterns('',
    (r'^$', login_required(authentic2.idp.views.homepage), {}, 'index'))

not_homepage_patterns = patterns('',
    url(r'^', include('authentic2.auth2_auth.urls')),
    url(r'^redirect/(.*)', 'authentic2.views.redirect'),
    url(r'^accounts/delete/', 'authentic2.views.delete_account', name='delete_account'),
    url(r'^accounts/password/change/done/', 'authentic2.views.password_change_done'),
    url(r'^accounts/register/complete/', 'authentic2.views.registration_success', name='registration_complete'),
    url(r'^accounts/register/',
       'registration.views.register',
       {'backend':'authentic2.registration_backend.SimpleBackend',
        'success_url' : '/',
        'form_class': AuthenticRegistrationForm },
       name='registration_register',
       ),
    url(r'^accounts/', include('registration.backends.simple.urls')),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^admin_tools/', include('admin_tools.urls')),
    url(r'^idp/', include('authentic2.idp.urls')),
    url(r'^logout/$', 'authentic2.idp.views.logout', name='auth_logout'),
    url(r'^profile/edit/$', 'authentic2.views.edit_profile',
        name='profile_edit'),
    url(r'^profile/$',
        prevent_access_to_transient_users(authentic2.idp.views.profile), {},
        'account_management'),
)

urlpatterns += not_homepage_patterns

urlpatterns += patterns('',
    (r'^authsaml2/', include('authentic2.authsaml2.urls')),
)

if getattr(settings, 'IDP_OPENID', False):
    urlpatterns += patterns('',
            (r'^openid/', include('authentic2.idp.idp_openid.urls')))

if 'authentic2.auth2_auth.auth2_oath' in settings.INSTALLED_APPS:
    urlpatterns += patterns('',
            (r'^oath/', include('authentic2.auth2_auth.auth2_oath.urls')))

try:
    if settings.DISCO_SERVICE:
        urlpatterns += patterns('',
            (r'^disco_service/', include('disco_service.disco_responder')),
        )
except:
    pass
