import json

from django.views.generic import (TemplateView, FormView, UpdateView,
        CreateView)
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.translation import ugettext_lazy as _
from django.forms import models as model_forms

from django.contrib.auth.models import Group
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import permission_required

from django.contrib import messages

from django_tables2 import RequestConfig

from authentic2.compat import get_user_model

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

class ActionMixin(object):
    action = None

    def get_context_data(self, **kwargs):
        ctx = super(ActionMixin, self).get_context_data(**kwargs)
        if self.action:
            ctx['action'] = self.action
        return ctx

class OtherActionsMixin(object):
    other_actions = None

    def get_context_data(self, **kwargs):
        ctx = super(OtherActionsMixin, self).get_context_data(**kwargs)
        if self.get_other_actions():
            ctx['other_actions'] = self.get_other_actions()
        return ctx

    def get_other_actions(self):
        return self.other_actions or ()

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        for action, title in self.get_other_actions():
            if action in request.POST:
                method = getattr(self, 'action_' + action, None)
                if method:
                    response = method(request, *args, **kwargs)
                    if response:
                        return response
                self.request.method = 'GET'
                return self.get(request, *args, **kwargs)
        return super(OtherActionsMixin, self).post(request, *args, **kwargs)


class RoleAddView(TitleMixin, AjaxFormViewMixin, FormView):
    template_name = 'authentic2/manager/form.html'
    form_class = forms.RoleAddForm
    title = _('Add new role')

    def form_valid(self, form):
        super(RoleAddView, self).form_valid(form)
        return redirect('a2-manager-role', role_ref=self.form_result)

class RoleEditView(TitleMixin, AjaxFormViewMixin, UpdateView):
    template_name = 'authentic2/manager/form.html'
    title = _('Edit role')
    model = Group
    pk_url_kwarg = 'role_ref'
    fields = ['name']

    def get_form_class(self):
        return model_forms.modelform_factory(self.model, fields=self.fields)


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
        ref = request.POST.get('ref')
        if ref:
            action = request.POST.get('action', 'add')
            if action == 'add':
                utils.add_user_to_role(role, ref)
            elif action == 'remove':
                utils.remove_user_from_role(role, ref)
        if 'delete' in request.GET:
            utils.delete_role(role)
            return HttpResponseRedirect('..')
        return HttpResponseRedirect('')



roles = permission_required('group.add', raise_exception=True)(RolesView.as_view())
role_add = permission_required('group.add', raise_exception=True)(RoleAddView.as_view())
role_edit = permission_required('group.change', raise_exception=True)(RoleEditView.as_view())
role = permission_required('group.delete', raise_exception=True)(RoleView.as_view())

class UsersView(RolesMixin, TemplateView):
    template_name = 'authentic2/manager/users.html'

    def get_context_data(self, **kwargs):
        ctx = super(UsersView, self).get_context_data(**kwargs)
        if 'search' in self.request.GET:
            kwargs = {'search': self.request.GET['search']}
        users = utils.get_users(**kwargs)
        ctx['users'] = users
        table = tables.UserTable(users)
        RequestConfig(self.request).configure(table)
        ctx['table'] = table
        return ctx

class UserMixin(object):
    model = get_user_model()
    template_name = 'authentic2/manager/form.html'
    fields = ['username', 'first_name', 'last_name', 'email', 'is_active']
    form_class = forms.UserEditForm

class UserAddView(UserMixin, ActionMixin, TitleMixin,
        AjaxFormViewMixin, CreateView):
    title = _('Create user')
    action = _('Create')

class UserEditView(UserMixin, OtherActionsMixin, ActionMixin, TitleMixin,
        AjaxFormViewMixin, UpdateView):
    title = _('Edit user')
    action = _('Edit')
    fields = ['username', 'first_name', 'last_name', 'email']
    other_actions = (
            ('password_reset', _('Reset password')),
            ('activate', _('Activate')),
            ('deactivate', _('Deactivate')),
            ('delete', _('Delete')),
    )

    def get_other_actions(self):
        other_actions = list(super(UserEditView, self).get_other_actions())
        removed = 'activate' if self.object.is_active else 'deactivate'
        return filter(lambda x: x[0] != removed, other_actions)

    def action_activate(self, request, *args, **kwargs):
        self.object.is_active = True
        self.object.save()

    def action_deactivate(self, request, *args, **kwargs):
        self.object.is_active = False
        self.object.save()

    def action_password_reset(self, request, *args, **kwargs):
        # FIXME: a bit hacky, could break if PasswordResetForm implementation changes
        # copied from django.contrib.auth.views and django.contrib.auth.forms
        form = PasswordResetForm()
        form.users_cache = [self.object]
        opts = {
            'use_https': request.is_secure(),
            'token_generator': default_token_generator,
            'request': request,
        }
        form.save(**opts)
        messages.info(request, _('A mail was sent to %s') % self.object.email)


users = permission_required('user.delete', raise_exception=True)(UsersView.as_view())
user_add = permission_required('user.add', raise_exception=True)(UserAddView.as_view())
user_edit = permission_required('user.change', raise_exception=True)(UserEditView.as_view())