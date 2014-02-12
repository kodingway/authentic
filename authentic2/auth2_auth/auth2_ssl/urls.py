from django.conf.urls import patterns, url

urlpatterns = patterns('authentic2.auth2_auth.auth2_ssl.login_ssl',
    url(r'^$', 'handle_request', name='user_signin_ssl'),
    url(r'^post_account_linking/$', name='post_account_linking'),
    url(r'^delete_certificate/$', name='delete_certificate'),
    url(r'^register/$', 'views.register', name='sslauth_register'),
    url(r'^error_ssl/$', 'error_ssl', name='error_ssl'),
)
