from django.utils.translation import ugettext_lazy as _
from django import forms
from django.contrib.auth.models import Group
from django.contrib.contenttypes.models import ContentType
from django.db.models.query import Q

from authentic2.compat import get_user_model
from authentic2.passwords import generate_password
from authentic2.utils import send_templated_mail

from django_rbac.models import Operation
from django_rbac.utils import get_ou_model, get_role_model

from authentic2.forms import BaseUserForm

from . import fields


class CssClass(object):
    error_css_class = 'error'
    required_css_class = 'required'


class PrefixFormMixin(object):
    def __init__(self, *args, **kwargs):
        kwargs['prefix'] = self.__class__.prefix
        super(PrefixFormMixin, self).__init__(*args, **kwargs)


class GroupAddForm(CssClass, forms.ModelForm):
    class Meta:
        fields = ('name',)
        model = Group


class LimitQuerysetFormMixin(object):
    '''Limit queryset of all model choice field based on the objects
       viewable by the user.
    '''
    field_view_permisions = None

    def __init__(self, *args, **kwargs):
        self.request = request = kwargs.pop('request', None)
        super(LimitQuerysetFormMixin, self).__init__(*args, **kwargs)
        if request and not request.user.is_anonymous():
            for name, field in self.fields.iteritems():
                qs = getattr(field, 'queryset', None)
                if not qs:
                    continue
                if self.field_view_permisions \
                   and name in self.field_view_permisions:
                    perm = self.field_view_permisions[name]
                else:
                    app_label = qs.model._meta.app_label
                    model_name = qs.model._meta.model_name
                    perm = '%s.view_%s' % (app_label, model_name)
                qs = request.user.filter_by_perm(perm, qs)
                field.queryset = qs


class ChooseUserForm(CssClass, forms.Form):
    user = fields.ChooseUserField(label=_('Add an user'))
    action = forms.CharField(initial='add', widget=forms.HiddenInput)


class ChooseRoleForm(CssClass, forms.Form):
    role = fields.ChooseRoleField(label=_('Add a role'))
    action = forms.CharField(initial='add', widget=forms.HiddenInput)


class ChooseOUForm(CssClass, forms.Form):
    role = fields.ChooseRoleField(label=_('Organizational unit'))


class ChoosePermissionForm(CssClass, forms.Form):
    operation = forms.ModelChoiceField(queryset=Operation.objects)
    ou = forms.ModelChoiceField(queryset=get_ou_model().objects,
                                required=False)
    target = forms.ModelChoiceField(queryset=ContentType.objects)
    action = forms.CharField(initial='add', widget=forms.HiddenInput)


class UserEditForm(LimitQuerysetFormMixin, CssClass, BaseUserForm):
    ou = fields.ChooseOUField(required=True, label=_('Organizational unit'))
    groups = fields.GroupsField(label=_('Groups'), required=False)
    roles = fields.RolesField(label=_('Roles'), required=False)

    field_view_permisions = {
        'groups': 'auth.change_group',
        'roles': 'a2_rbac.change_role',
    }

    def __init__(self, *args, **kwargs):
        request = kwargs.get('request')
        if kwargs.get('instance') and kwargs['instance'].pk:
            initial = kwargs.setdefault('initial', {})
            roles = kwargs['instance'].roles.all()
            if request and not request.user.is_anonymous():
                roles = request.user.filter_by_perm(
                    'a2_rbac.change_role', roles)
            initial['roles'] = [role.pk for role in roles]
        super(UserEditForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):
        # roles is a virtual field, we must save it manually
        user = super(UserEditForm, self).save(commit=commit)
        roles = list(self.cleaned_data['roles'])

        def save_roles():
            visible_roles = self.request.user.filter_by_perm(
                'a2_rbac.change_role', user.roles.all())
            for role in visible_roles:
                if role not in roles:
                    user.roles.remove(role)
            for role in roles:
                if role not in visible_roles:
                    user.roles.add(role)
        if commit:
            save_roles()
        else:
            old_save = user.save

            def save(*args, **kwargs):
                user = old_save(*args, **kwargs)
                save_roles()
                return user
            user.save = save
        return user

    class Meta:
        model = get_user_model()
        fields = ('ou', 'groups')


class UserChangePasswordForm(CssClass, forms.ModelForm):
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }
    notification_template_prefix = \
        'authentic2/manager/change-password-notification'

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def clean(self):
        if not self.cleaned_data.get('generate_new_password') \
                and not self.cleaned_data.get('password1'):
            raise forms.ValidationError(
                _('You must choose password generation or type a new'
                  '  one'))

    def save(self, commit=True):
        user = super(UserChangePasswordForm, self).save(commit=False)
        if self.cleaned_data['generate_new_password']:
            new_password = generate_password()
        else:
            new_password = self.cleaned_data["password1"]
        user.set_password(new_password)
        if self.cleaned_data['generate_new_password'] \
                or self.cleaned_data['send_mail']:
            old_save = user.save

            def save(*args, **kwargs):
                ret = old_save(*args, **kwargs)
                send_templated_mail(
                    user,
                    self.notification_template_prefix,
                    ctx={'new_password': new_password, 'user': user})
                return ret
            user.save = save
        if commit:
            user.save()
            if hasattr(self, 'save_m2m'):
                self.save_m2m()
        return user

    generate_new_password = forms.BooleanField(
        initial=False,
        label=_('Generate and send a new password'),
        required=False)
    send_mail = forms.BooleanField(
        initial=True,
        label=_('Send mail to user with the new password'),
        required=False)

    password1 = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput,
        required=False)
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput,
        help_text=_("Enter the same password as above, for verification."),
        required=False)

    class Meta:
        model = get_user_model()
        fields = ()


class UserAddForm(UserChangePasswordForm,
                  UserEditForm):
    notification_template_prefix = \
        'authentic2/manager/new-account-notification'

    generate_new_password = forms.BooleanField(
        initial=False,
        label=_('Generate and send a new password'),
        required=False)
    send_mail = forms.BooleanField(
        initial=True,
        label=_('Send mail to user with the new password'),
        required=False)

    password1 = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput,
        required=False)
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput,
        help_text=_("Enter the same password as above, for verification."),
        required=False)

    class Meta:
        model = get_user_model()
        fields = ()
        fields = ['username', 'ou', 'first_name', 'last_name', 'email',
                  'is_active', 'groups', 'roles', 'password1',
                  'password2']


class GroupPermissionsForm(CssClass, forms.ModelForm):
    permissions = fields.PermissionChoices()

    class Meta:
        model = Group
        fields = ('name', 'permissions',)


class RoleSearchForm(CssClass, PrefixFormMixin, forms.Form):
    prefix = 'search'

    text = forms.CharField(
        label=_('Name'),
        required=False)
    ou = fields.ChooseOUField(
        label=_('Organizational unit'),
        required=False)
    service = fields.ChooseServiceField(
        label=_('Service'),
        required=False)

    def filter(self, qs):
        if self.cleaned_data.get('ou'):
            qs = qs.filter(ou=self.cleaned_data['ou'])
        if self.cleaned_data.get('service'):
            qs = qs.filter(service=self.cleaned_data['service'])
        if self.cleaned_data.get('text'):
            qs = qs.filter(name__icontains=self.cleaned_data['text'])
        return qs


class UserSearchForm(CssClass, PrefixFormMixin, forms.Form):
    prefix = 'search'

    text = forms.CharField(
        label=_('Name'),
        required=False)
    ou = fields.ChooseOUField(
        label=_('Organizational unit'),
        required=False)

    def filter(self, qs):
        if self.cleaned_data.get('ou'):
            qs = qs.filter(ou=self.cleaned_data['ou'])
        if self.cleaned_data.get('text'):
            queries = []
            for term in self.cleaned_data['text'].split():
                queries.append(
                    Q(first_name__icontains=term)
                    | Q(last_name__icontains=term)
                    | Q(username__icontains=term)
                    | Q(email__icontains=term))
            qs = qs.filter(reduce(Q.__and__, queries))
        return qs


class NameSearchForm(CssClass, PrefixFormMixin, forms.Form):
    prefix = 'search'

    text = forms.CharField(
        label=_('Name'),
        required=False)

    def filter(self, qs):
        if self.cleaned_data.get('text'):
            qs = qs.filter(name__icontains=self.cleaned_data['text'])
        return qs


class RoleEditForm(LimitQuerysetFormMixin, CssClass, forms.ModelForm):
    ou = fields.ChooseOUField(
        label=_('Organizational unit'),
        required=True)

    class Meta:
        model = get_role_model()
        fields = ('name', 'slug', 'ou', 'description')

class OUEditForm(CssClass, forms.ModelForm):
    class Meta:
        model = get_ou_model()
        fields = ('name', 'slug', 'default')
