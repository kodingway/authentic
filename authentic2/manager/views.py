import json

from django.views.generic import TemplateView, FormView
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.translation import ugettext_lazy as _

from django_tables2 import RequestConfig

from . import app_settings, utils, tables, forms

class ManagerMixin(object):
    def get_context_data(self, **kwargs):
        ctx = super(ManagerMixin, self).get_context_data(**kwargs)
        ctx['management_homepage_url'] = app_settings.HOMEPAGE_URL or '/'
        ctx['management_logout_url'] = app_settings.LOGOUT_URL or '/accounts/logout'
        return ctx

class RolesMixin(ManagerMixin):
    def get_context_data(self, **kwargs):
        ctx = super(ManagerMixin, self).get_context_data(**kwargs)
        ctx['roles'] = utils.get_roles()
        ctx['role_add_form'] = forms.RoleAddForm()
        return ctx

class AjaxFormViewMixin(object):
    template_name = 'authentic2/manager/form.html'
    success_url = '.'

    def form_valid(self, form):
        if hasattr(form, 'save'):
            self.form_result = form.save()
        return super(AjaxFormViewMixin, self).form_valid(form)

    def dispatch(self, request, *args, **kwargs):
        response = super(AjaxFormViewMixin, self).dispatch(request, *args, **kwargs)
        if not request.is_ajax():
            return response
        data = {}
        if 'Location' in response:
            data['location'] = response['Location']
        if hasattr(response, 'render'):
            response.render()
            data['content'] = response.content
        return HttpResponse(json.dumps(data), content_type='application/json')

class RolesView(RolesMixin, TemplateView):
    template_name = 'authentic2/manager/roles.html'

class TitleMixin(object):
    title = None

    def get_context_data(self, **kwargs):
        ctx = super(TitleMixin, self).get_context_data(**kwargs)
        if self.title:
            ctx['title'] = self.title
        return ctx

class RoleAddView(TitleMixin, AjaxFormViewMixin, FormView):
    form_class = forms.RoleAddForm
    title = _('Add new role')

    def form_valid(self, form):
        super(RoleAddView, self).form_valid(form)
        return redirect('a2-manager-role', role_ref=self.form_result)



class RoleView(RolesMixin, TemplateView):
    template_name = 'authentic2/manager/role.html'

    def get_role(self):
        return utils.get_role(self.kwargs['role_ref'])

    def get_context_data(self, **kwargs):
        ctx = super(RoleView, self).get_context_data(**kwargs)
        ctx['active_role'] = self.get_role()
        kwargs = {}
        if 'search' in self.request.GET:
            kwargs = {'search': self.request.GET['search']}
        users = utils.get_role_users(ctx['active_role'], **kwargs)
        table = tables.UserTable(users)
        RequestConfig(self.request).configure(table)
        ctx['users'] = table
        ctx['choose_user_form'] = forms.ChooseUserForm()
        return ctx

    def post(self, request, *args, **kwargs):
        role = self.get_role()
        ref = request.POST.get('user')
        if ref:
            action = request.POST.get('action', 'add')
            if action == 'add':
                utils.add_user_to_role(role, ref)
            elif action == 'remove':
                utils.remove_user_from_role(role, ref)
        return HttpResponseRedirect('')

roles = RolesView.as_view()
role_add = RoleAddView.as_view()
role = RoleView.as_view()
