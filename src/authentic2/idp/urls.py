from django.conf.urls import url, patterns

urlpatterns = patterns('authentic2.idp.interactions',
        url(r'^consent_federation', 'consent_federation',
            name='a2-consent-federation'),
        url(r'^consent_attributes', 'consent_attributes',
            name='a2-consent-attributes'))
