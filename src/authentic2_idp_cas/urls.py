from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns('',
        url('^login/$', views.login, name='a2-idp-cas-login'),
	url('^continue/$', views._continue, name='a2-idp-cas-continue'),
	url('^validate/$', views.validate, name='a2-idp-cas-validate'),
        url('^serviceValidate/$', views.service_validate,
            name='a2-idp-cas-service-validate'),
        url('^logout/$', views.logout, name='a2-idp-cas-logout'),
        url('^proxy/$', views.proxy, name='a2-idp-cas-proxy'),
	url('^proxyValidate/$', views.proxy_validate,
            name='a2-idp-cas-proxy-validate'),
)
