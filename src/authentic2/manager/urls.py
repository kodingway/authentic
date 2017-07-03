from django.conf.urls import patterns, url, include

from django.views.i18n import javascript_catalog
from django.contrib.auth.decorators import login_required
from . import views, role_views, ou_views, user_views, service_views
from ..decorators import required

urlpatterns = required(
    login_required, patterns(
        'authentic2.views',
        # homepage
        url(r'^$', views.homepage, name='a2-manager-homepage'),

        # Authentic2 users
        url(r'^users/$', user_views.users, name='a2-manager-users'),
        url(r'^users/export/(?P<format>csv|json|html|ods)/$',
            user_views.users_export, name='a2-manager-users-export'),
        url(r'^users/(?P<ou_pk>\d+)/add/$', user_views.user_add,
            name='a2-manager-user-add'),
        url(r'^users/(?P<pk>\d+)/$', user_views.user_detail,
            name='a2-manager-user-detail'),
        url(r'^users/(?P<pk>\d+)/edit/$', user_views.user_edit,
            name='a2-manager-user-edit'),
        url(r'^users/(?P<pk>\d+)/delete/$', user_views.user_delete,
            name='a2-manager-user-delete'),
        url(r'^users/(?P<pk>\d+)/roles/$',
            user_views.roles,
            name='a2-manager-user-roles'),
        url(r'^users/(?P<pk>\d+)/change-password/$',
            user_views.user_change_password,
            name='a2-manager-user-change-password'),
        # by uuid
        url(r'^users/uuid:(?P<slug>[a-z0-9]+)/$', user_views.user_edit,
            name='a2-manager-user-by-uuid-edit'),
        url(r'^users/uuid:(?P<slug>[a-z0-9]+)/roles/$',
            user_views.roles,
            name='a2-manager-user-by-uuid-roles'),
        url(r'^users/uuid:(?P<slug>[a-z0-9]+)/change-password/$',
            user_views.user_change_password,
            name='a2-manager-user-by-uuid-change-password'),

        # Authentic2 roles
        url(r'^roles/$', role_views.listing,
            name='a2-manager-roles'),
        url(r'^roles/add/$', role_views.add,
            name='a2-manager-role-add'),
        url(r'^roles/export/(?P<format>csv|json|html|ods)/$',
            role_views.export, name='a2-manager-roles-export'),
        url(r'^roles/(?P<pk>\d+)/$', role_views.members,
            name='a2-manager-role-members'),
        url(r'^roles/(?P<pk>\d+)/add-child/$', role_views.add_child,
            name='a2-manager-role-add-child'),
        url(r'^roles/(?P<pk>\d+)/add-parent/$', role_views.add_parent,
            name='a2-manager-role-add-parent'),
        url(r'^roles/(?P<pk>\d+)/remove-child/(?P<child_pk>\d+)/$',
            role_views.remove_child, name='a2-manager-role-remove-child'),
        url(r'^roles/(?P<pk>\d+)/remove-parent/(?P<parent_pk>\d+)/$',
            role_views.remove_parent, name='a2-manager-role-remove-parent'),

        url(r'^roles/(?P<pk>\d+)/add-admin-user/$', role_views.add_admin_user,
            name='a2-manager-role-add-admin-user'),
        url(r'^roles/(?P<pk>\d+)/remove-admin-user/(?P<user_pk>\d+)/$',
            role_views.remove_admin_user, name='a2-manager-role-remove-admin-user'),

        url(r'^roles/(?P<pk>\d+)/add-admin-role/$', role_views.add_admin_role,
            name='a2-manager-role-add-admin-role'),
        url(r'^roles/(?P<pk>\d+)/remove-admin-role/(?P<role_pk>\d+)/$',
            role_views.remove_admin_role, name='a2-manager-role-remove-admin-role'),

        url(r'^roles/(?P<pk>\d+)/export/(?P<format>csv|json|html|ods)/$',
            role_views.members_export,
            name='a2-manager-role-members-export'),
        url(r'^roles/(?P<pk>\d+)/delete/$', role_views.delete,
            name='a2-manager-role-delete'),
        url(r'^roles/(?P<pk>\d+)/edit/$', role_views.edit,
            name='a2-manager-role-edit'),
        url(r'^roles/(?P<pk>\d+)/permissions/$', role_views.permissions,
            name='a2-manager-role-permissions'),


        # Authentic2 organizational units
        url(r'^organizational-units/$', ou_views.listing,
            name='a2-manager-ous'),
        url(r'^organizational-units/add/$', ou_views.add,
            name='a2-manager-ou-add'),
        url(r'^organizational-units/(?P<pk>\d+)/$', ou_views.edit,
            name='a2-manager-ou-edit'),
        url(r'^organizational-units/(?P<pk>\d+)/delete/$', ou_views.delete,
            name='a2-manager-ou-delete'),

        # Services
        url(r'^services/$', service_views.listing,
            name='a2-manager-services'),
        url(r'^services/(?P<service_pk>\d+)/$', service_views.roles,
            name='a2-manager-service'),
        url(r'^services/(?P<service_pk>\d+)/edit/$', service_views.edit,
            name='a2-manager-service-edit'),

        # backoffice menu as json
        url(r'^menu.json$', views.menu_json),
    )
)

urlpatterns += patterns('',
        url(r'^jsi18n/$', javascript_catalog,
            {'packages': ('authentic2.manager',)},
            name='a2-manager-javascript-catalog'),
    url(r'^select2.json$', views.select2, name='django_select2-json'),
)
