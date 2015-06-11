from django.utils.translation import ugettext as _
from django.shortcuts import get_object_or_404

from authentic2.models import Service

from . import tables, views, forms, role_views


class ServicesView(views.BaseTableView):
    model = Service
    template_name = 'authentic2/manager/services.html'
    table_class = tables.ServiceTable
    search_form_class = forms.NameSearchForm

listing = ServicesView.as_view()


class ServiceView(views.SimpleSubTableView):
    search_form_class = forms.NameSearchForm
    model = Service
    pk_url_kwarg = 'service_pk'
    template_name = 'authentic2/manager/service.html'
    table_class = tables.ServiceRolesTable

    def get_table_queryset(self):
        return self.object.roles.all()

    def get(self, request, *args, **kwargs):
        result = super(ServiceView, self).get(request, *args, **kwargs)
        self.service = self.object
        return result

roles = ServiceView.as_view()


class ServiceEditView(views.BaseEditView):
    model = Service
    pk_url_kwarg = 'service_pk'
    template_name = 'authentic2/manager/form.html'
    title = _('Edit service')
    permissions = ['authentic2.change_service']
    fields = ['name', 'slug', 'ou']
    success_url = '..'

edit = ServiceEditView.as_view()


class ServiceRoleMixin(object):
    service_roles = True

    def dispatch(self, request, *args, **kwargs):
        self.service = get_object_or_404(Service, pk=kwargs['service_pk'])
        return super(ServiceRoleMixin, self).dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return super(ServiceRoleMixin, self).get_queryset() \
            .filter(service_id=self.kwargs['service_pk'])


class ServiceRoleMembersView(ServiceRoleMixin,
                             role_views.RoleMembersView):
    template_name = 'authentic2/manager/service_role_members.html'

role_members = ServiceRoleMembersView.as_view()


class ServiceRoleChildrenView(ServiceRoleMixin,
                              role_views.RoleChildrenView):
    template_name = 'authentic2/manager/service_role_children.html'

role_children = ServiceRoleChildrenView.as_view()


class ServiceRoleManagersView(ServiceRoleMixin,
                              role_views.RoleManagersView):
    template_name = 'authentic2/manager/service_role_managers.html'

role_managers = ServiceRoleManagersView.as_view()


class ServiceRoleManagerRolesView(ServiceRoleMixin,
                                  role_views.RoleManagersRolesView):
    template_name = 'authentic2/manager/service_role_managers_roles.html'

role_managers_roles = ServiceRoleManagerRolesView.as_view()
