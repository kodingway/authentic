from django.conf.urls import patterns, url, include
from django.conf import settings

urlpatterns = patterns('')

if settings.AUTH_OPENID:
    urlpatterns += patterns('',
        (r'^accounts/openid/',
            include('authentic2.auth2_auth.auth2_openid.urls')),
    )

if settings.AUTH_SSL:
    urlpatterns += patterns('',
        url(r'^sslauth/', include('authentic2.auth2_auth.auth2_ssl.urls')))
