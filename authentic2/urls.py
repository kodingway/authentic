from django.contrib.auth.decorators import login_required
from django.conf.urls.defaults import patterns, url, include

from authentic2.idp.decorators import prevent_access_to_transient_users

import authentic2.idp.views
import settings
from forms import AuthenticRegistrationForm

from .admin import admin

admin.autodiscover()
handler500 = 'authentic2.views.server_error'


urlpatterns = patterns('',
    (r'^', include('authentic2.auth2_auth.urls')),
    (r'^redirect/(.*)', 'authentic2.views.redirect'),
    url(r'^accounts/password/change/done', 'authentic2.views.password_change_done'),
    url(r'^accounts/register/registration_success', 'authentic2.views.registration_success', name='registration_success'),
    url(r'^accounts/register',
       'registration.views.register',
       {'backend':'registration.backends.default.DefaultBackend',
        'success_url' : 'registration_success',
        'form_class': AuthenticRegistrationForm },
       name='registration_register',
       ),
    (r'^accounts/', include('registration.backends.default.urls')),
    url(r'^logout$', 'authentic2.idp.views.logout', name='auth_logout'),
    (r'^admin/admin_log_view/log/', 'authentic2.admin_log_view.views.admin_view'),
    (r'^admin/', include(admin.site.urls)),
    (r'^idp/', include('authentic2.idp.urls')),
    (r'^logout$', 'authentic2.idp.views.logout'),
    (r'^$', login_required(authentic2.idp.views.homepage), {}, 'index'),
    (r'^profile$',
        prevent_access_to_transient_users(authentic2.idp.views.profile), {},
        'account_management'),
    url(r'^edit_profile$', 'authentic2.views.edit_profile',
        name='profiles_edit_profile'),
    url(r'^create_profile$', 'authentic2.views.create_profile',
        name='profiles_create_profile'),
)

urlpatterns += patterns('',
    (r'^authsaml2/', include('authentic2.authsaml2.urls')),
)

if settings.STATIC_SERVE:
    print 'static server'
    urlpatterns += patterns('django.contrib.staticfiles.views',
        url(r'^static/(?P<path>.*)$', 'serve'),
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
