import uuid

from django.db import models
from django.utils.translation import ugettext_lazy as _, ugettext
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.html import format_html
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.http import HttpResponseRedirect, QueryDict
from django.views.generic.detail import SingleObjectMixin
from django.views.generic import View

from authentic2.constants import SWITCH_USER_SESSION_KEY
from authentic2.models import Attribute, PasswordReset
from authentic2.utils import switch_user, send_password_reset_mail
from authentic2.a2_rbac.utils import get_default_ou
from authentic2 import hooks
from django_rbac.utils import get_role_model, get_role_parenting_model, get_ou_model


from .views import BaseTableView, BaseAddView, \
    BaseEditView, ActionMixin, OtherActionsMixin, Action, ExportMixin, \
    BaseSubTableView, HideOUColumnMixin, BaseDeleteView, BaseDetailView
from .tables import UserTable, UserRolesTable, OuUserRolesTable
from .forms import UserSearchForm, UserAddForm, UserEditForm, \
    UserChangePasswordForm, ChooseUserRoleForm, UserRoleSearchForm
from .resources import UserResource
from . import app_settings


class UsersView(HideOUColumnMixin, BaseTableView):
    template_name = 'authentic2/manager/users.html'
    model = get_user_model()
    table_class = UserTable
    permissions = ['custom_user.search_user']
    search_form_class = UserSearchForm

    def is_ou_specified(self):
        return self.search_form.is_valid() \
            and self.search_form.cleaned_data.get('ou')

    def get_queryset(self):
        return super(UsersView, self).get_queryset().select_related('ou').prefetch_related('roles',
                                                                      'roles__parent_relation__parent')

    def get_search_form_kwargs(self):
        kwargs = super(UsersView, self).get_search_form_kwargs()
        kwargs['initial'] = {'ou': self.request.user.ou_id}
        return kwargs

    def filter_by_search(self, qs):
        qs = super(UsersView, self).filter_by_search(qs)
        if not self.search_form.is_valid():
            qs = qs.filter(ou=self.request.user.ou)
        return qs

    def get_table(self, **kwargs):
        table = super(UsersView, self).get_table(**kwargs)
        limit = app_settings.USER_SEARCH_MINIMUM_CHARS
        text = self.search_form.cleaned_data.get('text')
        if limit and (not text or len(text) < limit):
            table.empty_text = _('Enter at least %d characters') % limit
        return table

users = UsersView.as_view()


class UserAddView(BaseAddView):
    model = get_user_model()
    title = _('Create user')
    action = _('Create')
    fields = [
        'username',
        'first_name',
        'last_name',
        'email',
        'generate_password',
        'password1',
        'password2',
        'reset_password_at_next_login',
        'send_mail']
    form_class = UserAddForm
    permissions = ['custom_user.add_user']
    template_name = 'authentic2/manager/user_add.html'

    def get_form_kwargs(self):
        kwargs = super(UserAddView, self).get_form_kwargs()
        qs = self.request.user.ous_with_perm('custom_user.add_user')
        self.ou = qs.get(pk=self.kwargs['ou_pk'])
        kwargs['ou'] = self.ou
        return kwargs

    def get_fields(self):
        fields = list(self.fields)
        i = fields.index('generate_password')
        if self.request.user.is_superuser and \
                'is_superuser' not in self.fields:
            fields.insert(i, 'is_superuser')
            i += 1
        for attribute in Attribute.objects.all():
            fields.insert(i, attribute.name)
            i += 1
        return fields

    def get_success_url(self):
        return reverse('a2-manager-user-detail', kwargs={'pk': self.object.pk})

    def get_context_data(self, **kwargs):
        kwargs['cancel_url'] = '../..'
        kwargs['ou'] = self.ou
        return super(UserAddView, self).get_context_data(**kwargs)

user_add = UserAddView.as_view()


class UserDetailView(OtherActionsMixin, BaseDetailView):
    model = get_user_model()
    fields = ['username', 'ou', 'first_name', 'last_name', 'email']
    form_class = UserEditForm
    template_name = 'authentic2/manager/user_detail.html'
    slug_field = 'uuid'

    @property
    def title(self):
        return self.object.get_full_name()

    def get_other_actions(self):
        for action in super(UserDetailView, self).get_other_actions():
            yield action
        yield Action('password_reset', _('Reset password'),
                     permission='custom_user.reset_password_user')
        if self.object.is_active:
            yield Action('deactivate', _('Suspend'),
                         permission='custom_user.activate_user')
        else:
            yield Action('activate', _('Activate'),
                         permission='custom_user.activate_user')
        if PasswordReset.objects.filter(user=self.object).exists():
            yield Action('delete_password_reset', _('Do not force password change on next login'),
                         permission='custom_user.reset_password_user')
        else:
            yield Action('force_password_change', _('Force password change on '
                         'next login'),
                         permission='custom_user.reset_password_user')
        yield Action('change_password', _('Change user password'),
                     url_name='a2-manager-user-change-password',
                     permission='custom_user.change_password_user')
        if self.request.user.is_superuser:
            yield Action('switch_user', _('Impersonate this user'))

    def action_force_password_change(self, request, *args, **kwargs):
        PasswordReset.objects.get_or_create(user=self.object)

    def action_activate(self, request, *args, **kwargs):
        self.object.is_active = True
        self.object.save()

    def action_deactivate(self, request, *args, **kwargs):
        if request.user == self.object:
            messages.warning(request, _('You cannot desactivate your own '
                             'user'))
        else:
            self.object.is_active = False
            self.object.save()

    def action_password_reset(self, request, *args, **kwargs):
        user = self.object
        if not user.email:
            messages.info(request, _('User has no email, it\'not possible to '
                                     'send him am email to reset its '
                                     'password'))
            return
        send_password_reset_mail(user, request=request)
        messages.info(request, _('A mail was sent to %s') % self.object.email)

    def action_delete_password_reset(self, request, *args, **kwargs):
        PasswordReset.objects.filter(user=self.object).delete()

    def action_switch_user(self, request, *args, **kwargs):
        return switch_user(request, self.object)

    # Copied from PasswordResetForm implementation
    def send_mail(self, subject_template_name, email_template_name,
                  context, to_email):
        """
        Sends a django.core.mail.EmailMultiAlternatives to `to_email`.
        """
        subject = loader.render_to_string(subject_template_name, context)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())
        body = loader.render_to_string(email_template_name, context)

        email_message = EmailMultiAlternatives(subject, body, to=[to_email])
        email_message.send()

    def get_fields(self):
        fields = list(self.fields)
        for attribute in Attribute.objects.all():
            fields.append(attribute.name)
        if self.request.user.is_superuser and \
                'is_superuser' not in self.fields:
            fields.append('is_superuser')
        return fields

    def get_form(self, *args, **kwargs):
        form = super(UserDetailView, self).get_form(*args, **kwargs)
        if 'email' in form.fields:
            if self.object.email_verified:
                comment = _('Email verified')
            else:
                comment = _('Email not verified')
            form.fields['email'].help_text = format_html('<b>{0}</b>', comment)
        return form

    def get_context_data(self, **kwargs):
        kwargs['default_ou'] = get_default_ou
        kwargs['can_change_roles'] = self.request.user.has_perm_any('a2_rbac.change_role')
        user_data = []
        user_data += [data for datas in hooks.call_hooks('manager_user_data', self, self.object)
                      for data in datas]
        kwargs['user_data'] = user_data
        ctx = super(UserDetailView, self).get_context_data(**kwargs)
        return ctx

user_detail = UserDetailView.as_view()


class UserEditView(OtherActionsMixin, ActionMixin, BaseEditView):
    model = get_user_model()
    template_name = 'authentic2/manager/user_edit.html'
    form_class = UserEditForm
    permissions = ['custom_user.change_user']
    fields = ['username', 'ou', 'first_name', 'last_name', 'email']
    success_url = '..'
    slug_field = 'uuid'
    action = _('Change')

    @property
    def title(self):
        return _('Edit user %s') % self.object.get_full_name()

    def get_fields(self):
        fields = list(self.fields)
        for attribute in Attribute.objects.all():
            fields.append(attribute.name)
        if self.request.user.is_superuser and \
                'is_superuser' not in self.fields:
            fields.append('is_superuser')
        return fields

user_edit = UserEditView.as_view()


# Mock object to disable Queryset specialization by django-import-export
class IterateIterable(object):
    def __init__(self, qs):
        self.qs = qs

    def __iter__(self):
        return self.qs.__iter__()


class UsersExportView(ExportMixin, UsersView):
    permissions = ['custom_user.view_user']
    resource_class = UserResource
    export_prefix = 'users-'

    def get_data(self):
        return IterateIterable(self.get_queryset())

users_export = UsersExportView.as_view()


class UserChangePasswordView(BaseEditView):
    template_name = 'authentic2/manager/form.html'
    model = get_user_model()
    form_class = UserChangePasswordForm
    permissions = ['custom_user.change_password_user']
    title = _('Change user password')
    success_url = '..'
    slug_field = 'uuid'

    def get_success_message(self, cleaned_data):
        if cleaned_data.get('send_mail'):
            return ugettext('New password sent to %s') % self.object.email
        else:
            return ugettext('New password set')


user_change_password = UserChangePasswordView.as_view()


class UserRolesView(HideOUColumnMixin, BaseSubTableView):
    model = get_user_model()
    form_class = ChooseUserRoleForm
    search_form_class = UserRoleSearchForm
    success_url = '.'
    slug_field = 'uuid'

    @property
    def template_name(self):
        if self.is_ou_specified():
            return 'authentic2/manager/user_ou_roles.html'
        else:
            return 'authentic2/manager/user_roles.html'

    @property
    def table_pagination(self):
        if self.is_ou_specified():
            return False
        return None

    @property
    def table_class(self):
        if self.is_ou_specified():
            return OuUserRolesTable
        else:
            return UserRolesTable

    def is_ou_specified(self):
        OU = get_ou_model()
        return (OU.objects.count() < 2
                or (self.search_form.is_valid() and self.search_form.cleaned_data.get('ou')))

    def get_table_queryset(self):
        if self.is_ou_specified():
            roles = self.object.roles.all()
            User = get_user_model()
            Role = get_role_model()
            RoleParenting = get_role_parenting_model()
            rp_qs = RoleParenting.objects.filter(child=roles)
            qs = Role.objects.all()
            qs = qs.prefetch_related(models.Prefetch(
                'child_relation', queryset=rp_qs, to_attr='via'))
            qs = qs.prefetch_related(models.Prefetch(
                'members', queryset=User.objects.filter(pk=self.object.pk),
                to_attr='member'))
            qs2 = self.request.user.filter_by_perm('a2_rbac.change_role', qs)
            managable_ids = map(str, qs2.values_list('pk', flat=True))
            qs = qs.extra(select={'has_perm': 'a2_rbac_role.id in (%s)' % ', '.join(managable_ids)})
            qs = qs.exclude(slug__startswith='_a2-managers-of-role')
            return qs
        else:
            return self.object.roles_and_parents()

    def get_table_data(self):
        qs = super(UserRolesView, self).get_table_data()
        if self.is_ou_specified():
            qs = list(qs)
        return qs

    def dispatch(self, request, *args, **kwargs):
        return super(UserRolesView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = self.object
        role = form.cleaned_data['role']
        action = form.cleaned_data['action']
        if self.request.user.has_perm('a2_rbac.change_role', role):
            if action == 'add':
                if user.roles.filter(pk=role.pk):
                    messages.warning(
                        self.request,
                        _('User {user} has already the role {role}.')
                        .format(user=user, role=role))
                else:
                    user.roles.add(role)
            elif action == 'remove':
                user.roles.remove(role)
        else:
            messages.warning(self.request, _('You are not authorized'))
        return super(UserRolesView, self).form_valid(form)

    def get_search_form_kwargs(self):
        kwargs = super(UserRolesView, self).get_search_form_kwargs()
        kwargs['user'] = self.object
        return kwargs

    def get_form_kwargs(self):
        kwargs = super(UserRolesView, self).get_form_kwargs()
        kwargs['user'] = self.object
        return kwargs


roles = UserRolesView.as_view()


class UserDeleteView(BaseDeleteView):
    model = get_user_model()

    def get_success_url(self):
        return reverse('a2-manager-users')

user_delete = UserDeleteView.as_view()
