from django.conf.urls import patterns, url

from . import api_views

urlpatterns = patterns('',
                       url(r'^register/$', api_views.register,
                           name='a2-api-register'),
                       url(r'^password-change/$', api_views.password_change,
                           name='a2-api-password-change'),
                       url(r'^user/$', api_views.user,
                           name='a2-api-user'),
                       url(r'^roles/(?P<role_uuid>[\w+]*)/members/(?P<member_uuid>[^/]+)/$', api_views.roles,
                           name='a2-api-role-member'),
                       url(r'^check-password/$', api_views.check_password,
                           name='a2-api-check-password'),
)
urlpatterns += api_views.router.urls
