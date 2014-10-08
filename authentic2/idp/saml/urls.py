from django.conf.urls import patterns, url

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
    url(r'^idp_sso/(.*)$', 'idp_sso'),
)
