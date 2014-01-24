from django.conf.urls import patterns, url, include
from django.conf import settings

urlpatterns = patterns('',
    url(r'^login/$', 'authentic2.auth2_auth.views.login', name='auth_login'),
)

if settings.AUTH_OPENID:
    urlpatterns += patterns('',
        (r'^accounts/openid/',
            include('authentic2.auth2_auth.auth2_openid.urls')),
    )

if settings.AUTH_SSL:
    urlpatterns += patterns('authentic2.auth2_auth.auth2_ssl.login_ssl',
        url(r'^sslauth/$', 'handle_request', name='user_signin_ssl'),
        url(r'^sslauth/post_account_linking/$', name='post_account_linking'),
        url(r'^sslauth/delete_certificate/$', name='delete_certificate'),
        url(r'^sslauth/register/$', 'views.register', name='sslauth_register'),
        url(r'^sslauth/error_ssl/$', 'error_ssl', name='error_ssl'),
    )
