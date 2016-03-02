from django.conf.urls import patterns, url, include

urlpatterns = patterns('', url(r'^accounts/saml/', include('mellon.urls')))
