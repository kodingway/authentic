from django.conf.urls import patterns, url

from . import views


__patterns = [
    url(r'^.well-known/openid-configuration$',
        views.openid_configuration,
        name='oidc-openid-configuration'),
    url(r'^idp/oidc/certs/$',
        views.certs,
        name='oidc-certs'),
    url(r'^idp/oidc/authorize/$',
        views.authorize,
        name='oidc-authorize'),
    url(r'^idp/oidc/token/$',
        views.token,
        name='oidc-token'),
    url(r'^idp/oidc/user_info/$',
        views.user_info,
        name='oidc-user-info'),
    url(r'^idp/oidc/logout/$',
        views.logout,
        name='oidc-logout'),
]

urlpatterns = patterns('', *__patterns)
