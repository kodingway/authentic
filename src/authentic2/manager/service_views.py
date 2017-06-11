from django.utils.translation import ugettext as _
from django.contrib import messages
from django.shortcuts import get_object_or_404

from authentic2.models import Service

from . import tables, views, forms, role_views


class ServicesView(views.HideOUColumnMixin, views.BaseTableView):
    model = Service
    template_name = 'authentic2/manager/services.html'
    table_class = tables.ServiceTable
    search_form_class = forms.NameSearchForm
    permissions = ['authentic2.view_service']

listing = ServicesView.as_view()


class ServiceView(views.SimpleSubTableView, role_views.RoleViewMixin, views.MediaMixin, views.FormView):
    search_form_class = forms.NameSearchForm
    model = Service
    pk_url_kwarg = 'service_pk'
    template_name = 'authentic2/manager/service.html'
    table_class = tables.ServiceRolesTable
    permissions = ['authentic2.view_service']
    form_class = forms.ChooseRoleForm
    success_url = '.'

    def get_table_queryset(self):
        return self.object.authorized_roles.all()

    def get(self, request, *args, **kwargs):
        result = super(ServiceView, self).get(request, *args, **kwargs)
        self.service = self.object
        return result

    def form_valid(self, form):
        role = form.cleaned_data['role']
        action = form.cleaned_data['action']
        if self.can_change:
            if action == 'add':
                if self.object.authorized_roles.filter(pk=role.pk).exists():
                    messages.warning(self.request, _('Role already authorized in this '
                                     'service.'))
                else:
                    self.object.add_authorized_role(role)
            elif action == 'remove':
                self.object.remove_authorized_role(role)
        else:
            messages.warning(self.request, _('You are not authorized'))
        return super(ServiceView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        kwargs['form'] = self.get_form()
        ctx = super(ServiceView, self).get_context_data(**kwargs)
        ctx['roles_table'] = tables.RoleTable(self.object.roles.all())
        return ctx


roles = ServiceView.as_view()


class ServiceEditView(views.BaseEditView):
    model = Service
    pk_url_kwarg = 'service_pk'
    template_name = 'authentic2/manager/form.html'
    title = _('Edit service')
    permissions = ['authentic2.change_service']
    fields = ['name', 'slug', 'ou', 'unauthorized_url']
    success_url = '..'

edit = ServiceEditView.as_view()
