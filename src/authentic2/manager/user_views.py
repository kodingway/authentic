import uuid

from django.db import models
from django.utils.translation import ugettext_lazy as _, ugettext
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.views.generic.detail import SingleObjectMixin
from django.views.generic import View

from authentic2.constants import SWITCH_USER_SESSION_KEY
from authentic2.models import Attribute, PasswordReset
from authentic2.utils import switch_user, send_password_reset_mail
from authentic2.a2_rbac.utils import get_default_ou
from django_rbac.utils import get_role_model, get_role_parenting_model, get_ou_model


from .views import BaseTableView, BaseAddView, PassRequestToFormMixin, \
    BaseEditView, ActionMixin, OtherActionsMixin, Action, ExportMixin, \
    BaseSubTableView, HideOUColumnMixin
from .tables import UserTable, UserRolesTable, OuUserRolesTable
from .forms import UserSearchForm, UserAddForm, UserEditForm, \
    UserChangePasswordForm, ChooseUserRoleForm, RoleSearchForm
from .resources import UserResource


class UsersView(HideOUColumnMixin, BaseTableView):
    template_name = 'authentic2/manager/users.html'
    model = get_user_model()
    table_class = UserTable
    permissions = 'custom_user.view_user'
    search_form_class = UserSearchForm

    def is_ou_specified(self):
        return self.search_form.is_valid() \
            and self.search_form.cleaned_data.get('ou')

    def get_queryset(self):
        return super(UsersView, self).get_queryset().select_related('ou').prefetch_related('roles',
                                                                      'roles__parent_relation__parent')


users = UsersView.as_view()


class UserAddView(PassRequestToFormMixin, BaseAddView):
    model = get_user_model()
    title = _('Create user')
    action = _('Create')
    fields = [
        'username',
        'ou',
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
        return reverse('a2-manager-user-edit', kwargs={'pk': self.object.pk})


user_add = UserAddView.as_view()


class UserEditView(PassRequestToFormMixin, OtherActionsMixin,
                   ActionMixin, BaseEditView):
    model = get_user_model()
    template_name = 'authentic2/manager/user_edit.html'
    form_class = UserEditForm
    permissions = ['custom_user.change_user']
    fields = ['username', 'ou', 'first_name', 'last_name', 'email']
    success_url = '..'

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

    def get_other_actions(self):
        yield Action('password_reset', _('Reset password'))
        if self.object.is_active:
            yield Action('deactivate', _('Deactivate'))
        else:
            yield Action('activate', _('Activate'))
        if PasswordReset.objects.filter(user=self.object).exists():
            yield Action('delete_password_reset', '', display=False)
        else:
            yield Action('force_password_change', _('Force password change on '
                         'next login'))
        yield Action('change_password', _('Change user password'),
                     url_name='a2-manager-user-change-password')
        if self.request.user.has_perm('custom_user.delete_user', self.object):
            yield Action('delete',
                         _('Delete'),
                         _('Do you really want to delete "%s" ?') %
                         self.object.username)
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

    def action_delete(self, request, *args, **kwargs):
        self.object.delete()
        return HttpResponseRedirect('..')

    def action_password_reset(self, request, *args, **kwargs):
        user = self.object
        if not user.email:
            messages.info(request, _('User has no email, it\'not possible to '
                                     'send him am email to reset its '
                                     'password'))
            return

        # An user without a password cannot reset it
        if not user.has_usable_password():
            user.set_password(uuid.uuid4().hex)
            user.save()

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

    def get_context_data(self, **kwargs):
        ctx = super(UserEditView, self).get_context_data(**kwargs)
        ctx['default_ou'] = get_default_ou
        return ctx

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
    title = _('Change user password')
    success_url = '..'

    def get_success_message(self, cleaned_data):
        if cleaned_data.get('send_mail'):
            return ugettext('New password sent to %s') % self.object.email
        else:
            return ugettext('New password set')


user_change_password = UserChangePasswordView.as_view()


class UserRolesView(HideOUColumnMixin, BaseSubTableView):
    model = get_user_model()
    form_class = ChooseUserRoleForm
    search_form_class = RoleSearchForm
    success_url = '.'

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

roles = UserRolesView.as_view()
