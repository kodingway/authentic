from django.conf.urls import url, patterns, include

from django.conf import settings

urlpatterns = patterns('')

if settings.IDP_SAML2:
    urlpatterns += patterns('',
        (r'^saml2/', include('authentic2.idp.saml.urls')),)

if settings.IDP_CAS:
    from authentic2.idp.idp_cas.views import Authentic2CasProvider
    urlpatterns += patterns('',
            ('^cas/', include(Authentic2CasProvider().url)))

if getattr(settings, 'IDP_OPENID', False):
   urlpatterns += patterns('',
            (r'^openid/', include('authentic2.idp.idp_openid.urls')))


urlpatterns += patterns('authentic2.idp.interactions',
        url(r'^consent_federation', 'consent_federation',
            name='a2-consent-federation'),
        url(r'^consent_attributes', 'consent_attributes',
            name='a2-consent-attributes'))
