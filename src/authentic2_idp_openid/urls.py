# vim: set ts=4 sw=4 : */

from django.conf.urls import patterns, url
from . import views

urlpatterns = patterns('authentic2.idp.idp_openid.views',
    url(r'^$',
        views.openid_server,
        name='a2-idp-openid-root'),
    url(r'^trustedroot/(?P<pk>\d+)/delete/$',
        views.openid_trustedroot_delete,
        name='trustedroot_delete'),
    url(r'^decide/$',
        views.openid_decide,
        name='a2-idp-openid-decide'),
    url(r'^xrds/$',
        views.openid_xrds,
        name='a2-idp-openid-xrds'),
    url(r'^(?P<id>.+)/xrds/$',
        views.openid_xrds,
        {'identity': True},
        name='a2-idp-openid-identity-xrds'),
    url(r'^(?P<id>.+)/$',
        views.openid_discovery,
        name='a2-idp-openid-identity'),
)
