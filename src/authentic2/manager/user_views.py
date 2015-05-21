from django.utils.translation import ugettext_lazy as _, ugettext
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.http import HttpResponseRedirect

from authentic2.models import Attribute, PasswordReset

from .views import BaseTableView, BaseAddView, PassRequestToFormMixin, \
    BaseEditView, ActionMixin, OtherActionsMixin, Action, ExportMixin, \
    BaseSubTableView
from .tables import UserTable, UserRolesTable
from .forms import UserSearchForm, UserAddForm, UserEditForm, \
    UserChangePasswordForm, ChooseUserRoleForm, NameSearchForm
from .resources import UserResource


class UsersView(BaseTableView):
    template_name = 'authentic2/manager/users.html'
    model = get_user_model()
    table_class = UserTable
    permissions = 'custom_user.view_user'
    search_form_class = UserSearchForm

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

    def get_success_url(self):
        return reverse('a2-manager-user-edit', kwargs={'pk': self.object.pk})


user_add = UserAddView.as_view()


class UserEditView(PassRequestToFormMixin, OtherActionsMixin,
                   ActionMixin, BaseEditView):
    model = get_user_model()
    title = _('Edit user')
    template_name = 'authentic2/manager/user_edit.html'
    form_class = UserEditForm
    permissions = ['custom_user.change_user']
    fields = ['username', 'ou', 'first_name', 'last_name', 'email']
    success_url = '..'

    def get_fields(self):
        fields = list(self.fields)
        for attribute in Attribute.objects.all():
            fields.append(attribute.name)
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
        # FIXME: a bit hacky, could break if PasswordResetForm implementation
        # changes copied from django.contrib.auth.views and
        # django.contrib.auth.forms
        user = self.object
        if not user.email:
            messages.info(request, _('User has no email, it\'not possible to '
                                     'send him am email to reset its '
                                     'password'))
            return
        site_name = domain = request.get_host()
        context = {
            'email': user.email,
            'domain': domain,
            'site_name': site_name,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'user': user,
            'token': default_token_generator.make_token(user),
            'protocol': 'https' if request.is_secure() else 'http',
        }

        subject_template_name = 'registration/password_reset_subject.txt'
        email_template_name = 'registration/password_reset_email.html'

        self.send_mail(subject_template_name, email_template_name,
                       context, user.email)

        messages.info(request, _('A mail was sent to %s') % self.object.email)

    def action_delete_password_reset(self, request, *args, **kwargs):
        PasswordReset.objects.filter(user=self.object).delete()

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

user_edit = UserEditView.as_view()


class UsersExportView(ExportMixin, UsersView):
    permissions = ['custom_user.view_user']
    resource_class = UserResource
    export_prefix = 'users-'

    def get_data(self):
        return self.get_queryset()


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


class UserRolesView(BaseSubTableView):
    model = get_user_model()
    template_name = 'authentic2/manager/user_roles.html'
    table_class = UserRolesTable 
    form_class = ChooseUserRoleForm
    search_form_class = NameSearchForm
    success_url = '.'

    def get_table_queryset(self):
        return self.object.roles_and_parents()

    def form_valid(self, form):
        user = self.object
        role = form.cleaned_data['role']
        action = form.cleaned_data['action']
        if self.request.user.has_perm('a2_rbac.change_role', role):
            if action == 'add':
                if user.roles.filter(pk=role.pk):
                    messages.warning(
                        self.request,
                        _('User {user} has already the role {role}.') \
                            .format(user=user, role=role))
                else:
                    user.roles.add(role)
            elif action == 'remove':
                user.roles.remove(role)
        else:
            messages.warning(self.request, _('You are not authorized'))
        return super(UserRolesView, self).form_valid(form)

roles = UserRolesView.as_view()
