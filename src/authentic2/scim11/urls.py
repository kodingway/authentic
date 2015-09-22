from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns(
    '',
    url(r'(?P<resource_endpoint>\w+)/(?P<resource_id>.*)$',
        views.scim11, name='a2-scim11'),

)
