from django.conf.urls import patterns, url
from .views import (handle_request, post_account_linking, delete_certificate,
        register, error_ssl)

urlpatterns = patterns('authentic2.auth2_auth.auth2_ssl.views',
    url(r'^$', 
        handle_request, 
        name='user_signin_ssl'),
    url(r'^post_account_linking/$',
        post_account_linking,
        name='post_account_linking'),
    url(r'^delete_certificate/(?P<certificate_pk>\d+)/$',
        delete_certificate,
        name='delete_certificate'),
    url(r'^register/$',
        register,
        name='sslauth_register'),
    url(r'^error_ssl/$',
        error_ssl,
        name='error_ssl'),
)
