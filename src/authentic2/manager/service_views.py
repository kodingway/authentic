from django.utils.translation import ugettext as _
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


class ServiceView(views.SimpleSubTableView):
    search_form_class = forms.NameSearchForm
    model = Service
    pk_url_kwarg = 'service_pk'
    template_name = 'authentic2/manager/service.html'
    table_class = tables.ServiceRolesTable
    permissions = ['authentic2.view_service']

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
