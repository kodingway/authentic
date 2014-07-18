from django.conf.urls import patterns, url, include

from . import views

urlpatterns = patterns('authentic2.views', 
        url(r'^roles/$', views.roles, name='a2-manager-roles'),
        url(r'^roles/add/$', views.role_add, name='a2-manager-role-add'),
        url(r'^roles/(?P<role_ref>[^/]*)/$', views.role, name='a2-manager-role'),
        url(r'^', include('django_select2.urls')),
   )
