from django.conf.urls import patterns, url

from . import api_views

urlpatterns = patterns('',
                       url(r'register/$', api_views.register,
                           name='a2-api-register'))
