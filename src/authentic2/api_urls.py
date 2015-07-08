from django.conf.urls import patterns, url

from . import api_views

urlpatterns = patterns('',
                       url(r'register/$', api_views.register,
                           name='a2-api-register'),
                       url(r'password-change/$', api_views.password_change,
                           name='a2-api-password-change'),
                       url(r'^user/$', api_views.user,
                           name='a2-api-user'),
)
