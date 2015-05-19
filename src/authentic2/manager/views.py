import json

from django.utils.encoding import force_bytes
from django.utils.text import slugify
from django.utils.http import urlsafe_base64_encode
from django.template import loader
from django.core.mail import EmailMultiAlternatives
from django.core.exceptions import PermissionDenied
from django.contrib.messages.views import SuccessMessageMixin

from django.views.generic import TemplateView, FormView, UpdateView, \
    CreateView, DeleteView, View
from django.views.generic.detail import SingleObjectMixin
from django.http import HttpResponse, HttpResponseRedirect
from django.utils.translation import ugettext_lazy as _, ugettext as _T
from django.utils.timezone import now
from django.forms import models as model_forms
from django.core.urlresolvers import reverse

from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import Group

from django.contrib import messages

from django_tables2 import SingleTableView, SingleTableMixin

from authentic2.compat import get_user_model
from authentic2.forms import modelform_factory
from authentic2.models import Attribute

from . import app_settings, tables, forms, resources

from authentic2.models import PasswordReset


class PermissionMixin(object):
    permissions = None

    def dispatch(self, request, *args, **kwargs):
        if hasattr(self, 'model'):
            app_label = self.model._meta.app_label
            model_name = self.model._meta.model_name
            add_perm = '%s.add_%s' % (app_label, model_name)
            self.can_add = request.user.has_perm_any(add_perm)
            if hasattr(self, 'get_object') \
                    and hasattr(self, 'pk_url_kwarg') \
                    and self.pk_url_kwarg in self.kwargs:
                self.object = self.get_object()
                view_perm = '%s.view_%s' % (app_label, model_name)
                change_perm = '%s.change_%s' % (app_label, model_name)
                delete_perm = '%s.delete_%s' % (app_label, model_name)
                self.can_view = request.user.has_perm(view_perm, self.object)
                self.can_change = request.user.has_perm(change_perm, self.object)
                self.can_delete = request.user.has_perm(delete_perm, self.object)
                if self.permissions \
                        and not request.user.has_perms(
                            self.permissions, self.object):
                    raise PermissionDenied
            elif self.permissions \
                    and not request.user.has_perm_any(self.permissions):
                raise PermissionDenied
        else:
            if self.permissions \
                    and not request.user.has_perm_any(self.permissions):
                raise PermissionDenied

        return super(PermissionMixin, self).dispatch(request, *args, **kwargs)


def filter_view(request, qs):
    model = qs.model
    perm = '%s.view_%s' % (model._meta.app_label, model._meta.model_name)
    return request.user.filter_by_perm(perm, qs)


class FilterQuerysetByPermMixin(object):
    def get_queryset(self):
        qs = super(FilterQuerysetByPermMixin, self).get_queryset()
        return filter_view(self.request, qs)


class FilterTableQuerysetByPermMixin(object):
    def get_table_data(self):
        qs = super(FilterTableQuerysetByPermMixin, self).get_table_data()
        return filter_view(self.request, qs)


class FilterDatasetQuerysetByPermMixin(object):
    def get_dataset(self):
        qs = super(FilterDatasetQuerysetByPermMixin, self).get_dataset()
        return filter_view(self.request, qs)


class TableQuerysetMixin(object):
    def get_table_queryset(self):
        return self.get_queryset()

    def get_table_data(self):
        return self.get_table_queryset()


class PassRequestToFormMixin(object):
    def get_form_kwargs(self):
        kwargs = super(PassRequestToFormMixin, self).get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs


class SearchFormMixin(object):
    search_form_class = None

    def get_search_form_class(self):
        return self.search_form_class

    def get_search_form_kwargs(self):
        return {'data': self.request.GET}

    def get_search_form(self):
        form_class = self.get_search_form_class()
        if not form_class:
            return
        return form_class(**self.get_search_form_kwargs())

    def dispatch(self, request, *args, **kwargs):
        self.search_form = self.get_search_form()
        return super(SearchFormMixin, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super(SearchFormMixin, self).get_context_data(**kwargs)
        if self.search_form:
            ctx['search_form'] = self.search_form
        return ctx

    def get_table_data(self):
        qs = super(SearchFormMixin, self).get_table_data()
        if self.search_form and self.search_form.is_valid():
            qs = self.search_form.filter(qs)
        return qs


class FormatsContextData(object):
    formats = ['csv', 'json', 'ods', 'html']

    def get_context_data(self, **kwargs):
        ctx = super(FormatsContextData, self).get_context_data(**kwargs)
        ctx['formats'] = self.formats
        return ctx


class Action(object):
    def __init__(self, name, title, confirm=None, display=True, url_name=None):
        self.name = name
        self.title = title
        self.confirm = confirm
        self.display = display
        self.url_name = url_name


class ManagerMixin(object):
    def get_context_data(self, **kwargs):
        ctx = super(ManagerMixin, self).get_context_data(**kwargs)
        ctx['logout_url'] = app_settings.LOGOUT_URL or reverse('auth_logout')
        return ctx


class AjaxFormViewMixin(object):
    success_url = '.'

    def dispatch(self, request, *args, **kwargs):
        response = super(AjaxFormViewMixin, self).dispatch(request, *args,
                                                           **kwargs)
        return self.return_ajax_response(request, response)

    def return_ajax_response(self, request, response):
        if not request.is_ajax():
            return response
        data = {}
        if 'Location' in response:
            location = response['Location']
            # empty location means that the view can be used from anywhere
            # and so the redirect URL should not be used
            # otherwise compute an absolute URI from the relative URI
            if location and (not location.startswith('http://') 
                             or not location.startswith('https://')
                             or not location.startswith('/')):
                location = request.build_absolute_uri(location)
            data['location'] = location
        if hasattr(response, 'render'):
            response.render()
            data['content'] = response.content
        return HttpResponse(json.dumps(data), content_type='application/json')


class TitleMixin(object):
    title = None

    def get_title(self):
        return self.title

    def get_context_data(self, **kwargs):
        ctx = super(TitleMixin, self).get_context_data(**kwargs)
        ctx['title'] = self.get_title()
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
        ctx['other_actions'] = tuple(self.get_displayed_other_actions())
        return ctx

    def get_other_actions(self):
        return self.other_actions or ()

    def get_displayed_other_actions(self):
        return [action for action in self.get_other_actions() if
                action.display]

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        for action in self.get_other_actions():
            if action.name in request.POST:
                method = getattr(self, 'action_' + action.name, None)
                if method:
                    response = method(request, *args, **kwargs)
                    if response:
                        return response
                self.request.method = 'GET'
                return self.get(request, *args, **kwargs)
        return super(OtherActionsMixin, self).post(request, *args, **kwargs)


class ExportMixin(object):
    export_prefix = ''

    def get_export_prefix(self):
        return self.export_prefix

    def get_dataset(self):
        return self.resource_class().export(self.get_data())

    def get(self, request, export_format, *args, **kwargs):
        content_types = {
            'csv': 'text/csv',
            'html': 'text/html',
            'json': 'application/json',
            'ods': 'application/vnd.oasis.opendocument.spreadsheet',
        }
        response = HttpResponse(getattr(self.get_dataset(), format),
                                content_type=content_types[format])
        filename = '%s%s.%s' % (self.get_export_prefix(), now().isoformat(),
                                export_format)
        response['Content-Disposition'] = 'attachment; filename="%s"' \
            % filename
        return response


class ModelNameMixin(object):
    def get_model_name(self):
        return self.model._meta.verbose_name

    def get_context_data(self, **kwargs):
        ctx = super(ModelNameMixin, self).get_context_data(**kwargs)
        ctx['model_name'] = self.get_model_name()
        return ctx


class BaseTableView(ModelNameMixin, PermissionMixin, SearchFormMixin,
                    FilterQuerysetByPermMixin, TableQuerysetMixin,
                    SingleTableView):
    pass


class BaseSubTableView(FormatsContextData, PermissionMixin,
                       SearchFormMixin, FilterTableQuerysetByPermMixin,
                       TableQuerysetMixin, SingleObjectMixin, SingleTableMixin,
                       FormView):
    success_url = '.'


class BaseDeleteView(TitleMixin, ModelNameMixin, PermissionMixin,
                     AjaxFormViewMixin, DeleteView):
    template_name = 'authentic2/manager/delete.html'

    def get_title(self):
        return _('Delete %s') % self.get_model_name()

    def get_success_url(self):
        return '../../'


class BaseAddView(TitleMixin, ModelNameMixin, PermissionMixin,
                  AjaxFormViewMixin, CreateView):
    template_name = 'authentic2/manager/form.html'
    success_view_name = None

    def get_title(self):
        return _('Add %s') % self.get_model_name()

    def get_success_url(self):
        return reverse(self.success_view_name, kwargs={'pk': self.object.pk})


class BaseEditView(TitleMixin, ModelNameMixin, PermissionMixin,
                   AjaxFormViewMixin, UpdateView):
    template_name = 'authentic2/manager/form.html'

    def get_title(self):
        return self.title or _('Edit %s') % self.get_model_name()

    def get_success_url(self):
        return '..'

#
# Group views
#


class GroupsViewMixin(object):
    model = Group


class GroupsView(GroupsViewMixin, BaseTableView):
    template_name = 'authentic2/manager/groups.html'
    table_class = tables.GroupTable
    search_form_class = forms.NameSearchForm


groups = GroupsView.as_view()


class GroupAddView(GroupsViewMixin, BaseAddView):
    template_name = 'authentic2/manager/form.html'
    form_class = forms.GroupAddForm
    title = _('Add new group')
    action = _('Create')
    permissions = 'auth.add_group'
    success_view_name = 'a2-manager-group'


group_add = GroupAddView.as_view()


class GroupDeleteView(GroupsViewMixin, BaseDeleteView):
    permissions = 'auth.delete_group'


group_delete = GroupDeleteView.as_view()


class GroupEditView(GroupsViewMixin, BaseEditView):
    fields = ['name']
    permissions = 'auth.edit_group'
    template_name = 'authentic2/manager/group_edit.html'

    def get_form_class(self):
        return model_forms.modelform_factory(self.model, fields=self.fields)


group_edit = GroupEditView.as_view()


class GroupMembersView(GroupsViewMixin, BaseSubTableView):
    template_name = 'authentic2/manager/group.html'
    table_class = tables.UserTable
    form_class = forms.ChooseUserForm
    search_form_class = forms.NameSearchForm

    def get_table_queryset(self):
        return self.object.user_set.all()

    def form_valid(self, form):
        if self.can_change:
            user = form.cleaned_data['user']
            action = form.cleaned_data['action']
            if action == 'add':
                if self.object.user_set.filter(pk=user.pk).exists():
                    messages.warning(self.request, _('User already in this '
                                     'group.'))
                else:
                    self.object.user_set.add(user)
            elif action == 'remove':
                self.object.user_set.remove(user)
        else:
            messages.warning(self.request, _('You are not authorized'))
        return super(GroupMembersView, self).form_valid(form)


group = GroupMembersView.as_view()


class GroupMembersExportView(GroupsViewMixin, ExportMixin, PermissionMixin,
                             SearchFormMixin, FilterQuerysetByPermMixin,
                             SingleObjectMixin, View):
    model = Group
    permissions = 'auth.view_group'
    resource_class = resources.UserResource

    def get_export_prefix(self):
        return u'group-%s-users-' % slugify(self.get_object().name)

    def get_data(self):
        return filter_view(self.request, self.get_object().user_set.all())


group_users_export = GroupMembersExportView.as_view()


class GroupPermissionsView(AjaxFormViewMixin, UpdateView):
    success_url = ".."
    template_name = 'authentic2/manager/group_change_permissions.html'
    model = Group
    form_class = forms.GroupPermissionsForm

group_permissions = GroupPermissionsView.as_view()


class UsersView(BaseTableView):
    template_name = 'authentic2/manager/users.html'
    model = get_user_model()
    table_class = tables.UserTable
    permissions = 'custom_user.view_user'
    search_form_class = forms.UserSearchForm

users = UsersView.as_view()


class UserMixin(object):
    model = get_user_model()
    template_name = 'authentic2/manager/form.html'

    def get_form_class(self):
        fields = list(self.fields)
        if self.request.user.is_superuser:
            fields.extend(['is_staff', 'is_superuser'])
        for attribute in Attribute.objects.all():
            fields.append(attribute.name)
        return modelform_factory(self.model, form=self.form_class,
                                 fields=fields)


class UserAddView(PassRequestToFormMixin, UserMixin, ActionMixin, TitleMixin,
                  AjaxFormViewMixin, CreateView):
    title = _('Create user')
    action = _('Create')
    fields = ['username', 'ou', 'first_name', 'last_name', 'email',
              'is_active', 'groups', 'roles', 'generate_new_password',
              'send_mail', 'password1', 'password2']
    form_class = forms.UserAddForm

    def get_success_url(self):
        return reverse('a2-manager-users')


user_add = UserAddView.as_view()


class UserEditView(PassRequestToFormMixin, UserMixin, OtherActionsMixin, ActionMixin, TitleMixin,
                   AjaxFormViewMixin, UpdateView):
    title = _('Edit user')
    template_name = 'authentic2/manager/user_edit.html'
    fields = ['username', 'ou', 'first_name', 'last_name', 'email',
              'groups', 'roles']
    form_class = forms.UserEditForm

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

    def get_success_url(self):
        if self.request.is_ajax():
            return ''
        else:
            return reverse('a2-manager-users')


user_edit = UserEditView.as_view()


class UsersExportView(UsersView):
    resource_class = resources.UserResource
    export_prefix = 'users-'

    def get_data(self):
        return self.get_queryset()


users_export = UsersExportView.as_view()


class UserChangePasswordView(AjaxFormViewMixin, SuccessMessageMixin,
                             TitleMixin, UpdateView):
    template_name = 'authentic2/manager/form.html'
    model = get_user_model()
    form_class = forms.UserChangePasswordForm
    title = _('Change user password')

    def get_success_message(self, cleaned_data):
        if cleaned_data.get('send_mail'):
            return _T('New password sent to %s') % self.object.email
        else:
            return _T('New password set')


user_change_password = UserChangePasswordView.as_view()


class HomepageView(PermissionMixin, ManagerMixin, TemplateView):
    template_name = 'authentic2/manager/homepage.html'
    permissions = ['a2_rbac.view_role', 'a2_rbac.view_organizationalunit',
                   'auth.view_group', 'custom_user.view_user']

homepage = HomepageView.as_view()
