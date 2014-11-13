from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns('authentic2.idp.saml.saml2_endpoints',
    url(r'^metadata$', 'metadata'),
    url(r'^sso$', 'sso'),
    url(r'^continue$', 'continue_sso'),
    url(r'^slo$', 'slo'),
    url(r'^slo/soap$', 'slo_soap'),
    url(r'^idp_slo/(.*)$', 'idp_slo'),
    url(r'^slo_return$', 'slo_return'),
    url(r'^finish_slo$', 'finish_slo'),
    url(r'^artifact$', 'artifact'),
    # legacy endpoint, now it's prefered to pass the entity_id in a parameter
    url(r'^idp_sso/(.+)$',
        'idp_sso'),
    url(r'^idp_sso/$',
        'idp_sso',
        name='a2-idp-saml2-idp-sso'),
    url(r'^federations/create/(?P<pk>\d+)/$',
        views.create_federation,
        name='a2-idp-saml2-federation-create'),
    url(r'^federations/(?P<pk>\d+)/delete/$',
        views.delete_federation,
        name='a2-idp-saml2-federation-delete'),
)
