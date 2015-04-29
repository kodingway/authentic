from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns('authentic2.idp.saml.saml2_endpoints',
    url(r'^metadata$', 'metadata', name='a2-idp-saml-metadata'),
    url(r'^sso$', 'sso', name='a2-idp-saml-sso'),
    url(r'^continue$', 'continue_sso', name='a2-idp-saml-continue'),
    url(r'^slo$', 'slo', name='a2-idp-saml-slo'),
    url(r'^slo/soap$', 'slo_soap', name='a2-idp-saml-slo-soap'),
    url(r'^idp_slo/(.*)$', 'idp_slo', name='a2-idp-saml-slo-idp'),
    url(r'^slo_return$', 'slo_return', name='a2-idp-saml-slo-return'),
    url(r'^finish_slo$', 'finish_slo', name='a2-idp-saml-finish-slo'),
    url(r'^artifact$', 'artifact', name='a2-idp-saml-artifact'),
    # legacy endpoint, now it's prefered to pass the entity_id in a parameter
    url(r'^idp_sso/(.+)$',
        'idp_sso', name='a2-idp-saml-idp-sso-named'),
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
