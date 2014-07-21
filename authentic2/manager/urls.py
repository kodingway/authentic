from django.conf.urls import patterns, url, include

from . import views

urlpatterns = patterns('authentic2.views', 
        url(r'^roles/$', views.roles, name='a2-manager-roles'),
        url(r'^roles/add/$', views.role_add, name='a2-manager-role-add'),
        url(r'^roles/(?P<role_ref>[^/]*)/$', views.role, name='a2-manager-role'),
        url(r'^roles/(?P<role_ref>[^/]*)/edit/$', views.role_edit, name='a2-manager-role-edit'),
        url(r'^users/$', views.users, name='a2-manager-users'),
        url(r'^users/add/$', views.user_add, name='a2-manager-user-add'),
        url(r'^users/(?P<pk>[^/]*)/$', views.user_edit, name='a2-manager-user-edit'),
        url(r'^', include('django_select2.urls')),
   )
