from django.conf.urls import url, patterns, include

from django.conf import settings

urlpatterns = patterns('')

if getattr(settings, 'IDP_SAML2', False):
    urlpatterns += patterns('',
        (r'^saml2/', include('authentic2.idp.saml.urls')),)

if getattr(settings, 'IDP_OPENID', False):
   urlpatterns += patterns('',
            (r'^openid/', include('authentic2.idp.idp_openid.urls')))


urlpatterns += patterns('authentic2.idp.interactions',
        url(r'^consent_federation', 'consent_federation',
            name='a2-consent-federation'),
        url(r'^consent_attributes', 'consent_attributes',
            name='a2-consent-attributes'))
