# vim: set ts=4 sw=4 : */

from django.conf.urls import patterns, url
from . import views

urlpatterns = patterns('authentic2.idp.idp_openid.views',
    url(r'^$',
        views.openid_server,
        name='openid-provider-root'),
    url(r'^trustedroot/(?P<pk>\d+)/delete/$',
        views.openid_trustedroot_delete,
        name='trustedroot_delete'),
    url(r'^decide/$',
        views.openid_decide,
        name='openid-provider-decide'),
    url(r'^xrds/$',
        views.openid_xrds,
        name='openid-provider-xrds'),
    url(r'^(?P<id>.+)/xrds/$',
        views.openid_xrds,
        {'identity': True},
        name='openid-provider-identity-xrds'),
    url(r'^(?P<id>.+)/$',
        views.openid_discovery,
        name='openid-provider-identity'),
)
