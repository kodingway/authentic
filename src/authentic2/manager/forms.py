import hashlib

from django.utils.translation import ugettext_lazy as _
from django import forms
from django.contrib.contenttypes.models import ContentType
from django.db.models.query import Q
from django.utils.text import slugify
from django.core.exceptions import ValidationError

from authentic2.compat import get_user_model
from authentic2.passwords import generate_password
from authentic2.utils import send_templated_mail

from django_rbac.models import Operation
from django_rbac.utils import get_ou_model, get_role_model, get_permission_model
from django_rbac.backends import DjangoRBACBackend

from authentic2.forms import BaseUserForm
from authentic2.models import PasswordReset
from authentic2.utils import import_module_or_class
from authentic2.a2_rbac.utils import get_default_ou

from . import fields, app_settings, utils


class CssClass(object):
    error_css_class = 'error'
    required_css_class = 'required'


class FormWithRequest(forms.Form):
    need_request = True

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request')
        super(FormWithRequest, self).__init__(*args, **kwargs)


class SlugMixin(forms.ModelForm):
    def save(self, commit=True):
        instance = self.instance
        if not instance.slug:
            instance.slug = slugify(unicode(instance.name)).lstrip('_')
            qs = instance.__class__.objects.all()
            if instance.pk:
                qs = qs.exclude(pk=instance.pk)
            i = 1
            while qs.filter(slug=instance.slug).exists():
                instance.slug += str(i)
                i += 1
        if len(instance.slug) > 256:
            instance.slug = instance.slug[:252] + \
                hashlib.md5(instance.slug).hexdigest()[:4]
        return super(SlugMixin, self).save(commit=commit)


class PrefixFormMixin(object):
    def __init__(self, *args, **kwargs):
        kwargs['prefix'] = self.__class__.prefix
        super(PrefixFormMixin, self).__init__(*args, **kwargs)


class LimitQuerysetFormMixin(FormWithRequest):
    '''Limit queryset of all model choice field based on the objects
       viewable by the user.
    '''
    field_view_permisions = None

    def __init__(self, *args, **kwargs):
        super(LimitQuerysetFormMixin, self).__init__(*args, **kwargs)
        if self.request and not self.request.user.is_anonymous():
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
                qs = self.request.user.filter_by_perm(perm, qs)
                field.queryset = qs
                assert qs.exists(), 'user has no view permissions on model %s' % qs.model


class ChooseUserForm(CssClass, forms.Form):
    user = fields.ChooseUserField(label=_('Add an user'))
    action = forms.CharField(initial='add', widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        ou = kwargs.pop('ou', None)
        super(ChooseUserForm, self).__init__(*args, **kwargs)
        if ou and app_settings.ROLE_MEMBERS_FROM_OU and ou:
            self.fields['user'].queryset = self.fields['user'].queryset.filter(ou=ou)


class ChooseRoleForm(CssClass, forms.Form):
    role = fields.ChooseRoleField(label=_('Add a role'))
    action = forms.CharField(initial='add', widget=forms.HiddenInput)


class UsersForm(CssClass, forms.Form):
    users = fields.ChooseUsersField(label=_('Add some users'))


class RoleForm(CssClass, forms.Form):
    role = fields.ChooseRoleField(label=_('Add a role'))


class RolesForm(CssClass, forms.Form):
    roles = fields.ChooseRolesField(label=_('Add some roles'))


class RolesForChangeForm(CssClass, forms.Form):
    roles = fields.ChooseRolesForChangeField(label=_('Add some roles'))


class ChooseUserRoleForm(CssClass, FormWithRequest, forms.Form):
    role = fields.ChooseUserRoleField(label=_('Add a role'))
    action = forms.CharField(initial='add', widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user')
        super(ChooseUserRoleForm, self).__init__(*args, **kwargs)
        if app_settings.ROLE_MEMBERS_FROM_OU and user.ou_id:
            self.fields['role'].queryset = self.fields['role'].queryset.filter(ou_id=user.ou_id)


class ChoosePermissionForm(CssClass, forms.Form):
    operation = forms.ModelChoiceField(
        required=False,
        label=_('Operation'),
        queryset=Operation.objects)
    ou = forms.ModelChoiceField(
        label=_('Organizational unit'),
        queryset=get_ou_model().objects,
        required=False)
    target = forms.ModelChoiceField(
        label=_('Target object'),
        required=False,
        queryset=ContentType.objects)
    action = forms.CharField(
        initial='add',
        required=False,
        widget=forms.HiddenInput)
    permission = forms.ModelChoiceField(
        queryset=get_permission_model().objects,
        required=False,
        widget=forms.HiddenInput)


class UserEditForm(LimitQuerysetFormMixin, CssClass, BaseUserForm):
    css_class = "user-form"
    form_id = "id_user_edit_form"

    def __init__(self, *args, **kwargs):
        request = kwargs.get('request')
        super(UserEditForm, self).__init__(*args, **kwargs)
        if 'ou' in self.fields and not request.user.is_superuser:
            field = self.fields['ou']
            field.required = True
            qs = field.queryset
            if self.instance and self.instance.pk:
                perm = 'custom_user.change_user'
            else:
                perm = 'custom_user.add_user'
            qs = DjangoRBACBackend().ous_with_perm(request.user, perm)
            field.queryset = qs
            count = qs.count()
            if count == 1:
                field.initial = qs[0].pk
            if count < 2:
                field.widget.attrs['disabled'] = ''
            if self.is_bound and count == 1:
                self.data._mutable = True
                self.data[self.add_prefix('ou')] = qs[0].pk
                self.data._mutable = False

    def clean(self):
        if not self.cleaned_data.get('username') and \
           not self.cleaned_data.get('email'):
            raise forms.ValidationError(
                _('You must set a username or an email.'))

    class Meta:
        model = get_user_model()
        exclude = ('ou', 'is_staff', 'groups', 'user_permissions', 'last_login',
                   'date_joined', 'password')


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
        if not self.cleaned_data.get('generate_password') \
                and not self.cleaned_data.get('password1'):
            raise forms.ValidationError(
                _('You must choose password generation or type a new'
                  '  one'))
        if (self.instance and self.instance.pk and not self.instance.email and
            (self.cleaned_data.get('send_mail')
             or self.cleaned_data.get('generate_password'))):
            raise forms.ValidationError(
                _('User does not have a mail, we cannot send the '
                  'informations to him.'))

    def save(self, commit=True):
        user = super(UserChangePasswordForm, self).save(commit=False)

        if self.cleaned_data['generate_password']:
            new_password = generate_password()
        else:
            new_password = self.cleaned_data["password1"]

        user.set_password(new_password)

        if commit:
            user.save()
            if hasattr(self, 'save_m2m'):
                self.save_m2m()

        if self.cleaned_data['generate_password'] \
                or self.cleaned_data['send_mail']:
            send_templated_mail(
                user,
                self.notification_template_prefix,
                context={'new_password': new_password, 'user': user})
        return user

    generate_password = forms.BooleanField(
        initial=False,
        label=_('Generate new password'),
        required=False)
    password1 = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput,
        required=False)
    password2 = forms.CharField(
        label=_("Confirmation"),
        widget=forms.PasswordInput,
        help_text=_("Enter the same password as above, for verification."),
        required=False)
    send_mail = forms.BooleanField(
        initial=True,
        label=_('Send informations to user'),
        required=False)

    class Meta:
        model = get_user_model()
        fields = ()


class UserAddForm(UserChangePasswordForm, UserEditForm):
    css_class = "user-form"
    form_id = "id_user_add_form"

    notification_template_prefix = \
        'authentic2/manager/new-account-notification'
    reset_password_at_next_login = forms.BooleanField(
        initial=False,
        label=_('Ask for password reset on next login'),
        required=False)

    def __init__(self, *args, **kwargs):
        self.ou = kwargs.pop('ou', None)
        super(UserAddForm, self).__init__(*args, **kwargs)

    def clean(self):
        super(UserAddForm, self).clean()
        if not self.cleaned_data.get('username') and \
           not self.cleaned_data.get('email'):
            raise forms.ValidationError(
                _('You must set a username or an email.'))

    def save(self, commit=True):
        self.instance.ou = self.ou
        user = super(UserAddForm, self).save(commit=commit)
        if self.cleaned_data.get('reset_password_at_next_login'):
            if commit:
                PasswordReset.objects.get_or_create(user=user)
            else:
                old_save = user.save

                def save(*args, **kwargs):
                    old_save(*args, **kwargs)
                    PasswordReset.objects.get_or_create(user=user)
                user.save = save
        return user

    class Meta:
        model = get_user_model()
        fields = '__all__'


class ServiceRoleSearchForm(CssClass, PrefixFormMixin, FormWithRequest):
    prefix = 'search'

    text = forms.CharField(
        label=_('Name'),
        required=False)
    internals = forms.BooleanField(
        initial=False,
        label=_('Show internal roles'),
        required=False)

    def __init__(self, *args, **kwargs):
        super(ServiceRoleSearchForm, self).__init__(*args, **kwargs)
        if app_settings.SHOW_INTERNAL_ROLES:
            del self.fields['internals']

    def filter(self, qs):
        if hasattr(super(ServiceRoleSearchForm, self), 'filter'):
            qs = super(ServiceRoleSearchForm, self).filter(qs)
        if self.cleaned_data.get('text'):
            qs = qs.filter(name__icontains=self.cleaned_data['text'])
        if not app_settings.SHOW_INTERNAL_ROLES and not self.cleaned_data.get('internals'):
            qs = qs.exclude(slug__startswith='_a2')
        return qs


class HideOUFieldMixin(object):
    def __init__(self, *args, **kwargs):
        super(HideOUFieldMixin, self).__init__(*args, **kwargs)
        OU = get_ou_model()
        if OU.objects.count() < 2:
            del self.fields['ou']

    def save(self, *args, **kwargs):
        if 'ou' not in self.fields:
            self.instance.ou = get_default_ou()
        return super(HideOUFieldMixin, self).save(*args, **kwargs)


class OUSearchForm(FormWithRequest):
    ou_permission = None

    ou = forms.ModelChoiceField(queryset=get_ou_model().objects,
                                required=True, label=_('Organizational unit'))

    def __init__(self, *args, **kwargs):
        request = kwargs['request']
        ou_qs = (kwargs.pop('ou_queryset', None)
                 or request.user.ous_with_perm(self.ou_permission).order_by('name'))
        data = kwargs.setdefault('data', {}).copy()
        kwargs['data'] = data
        if 'search-ou' not in data:
            if request.user.ou in ou_qs:
                data['search-ou'] = request.user.ou.pk
            elif len(ou_qs):
                data['search-ou'] = ou_qs[0].pk
        super(OUSearchForm, self).__init__(*args, **kwargs)
        if not request.user.is_superuser:
            self.fields['ou'].empty_label = None
        else:
            self.fields['ou'].required = False
        self.fields['ou'].queryset = ou_qs
        if len(ou_qs) < 2:
            self.fields['ou'].widget.attrs['disabled'] = ''

    def filter_no_ou(self, qs):
        if self.request.user.is_superuser:
            qs = qs.filter(ou__isnull=True)
        else:
            qs = qs.none()
        return qs

    def filter(self, qs):
        if hasattr(super(OUSearchForm, self), 'filter'):
            qs = super(OUSearchForm, self).filter(qs)
        if self.cleaned_data.get('ou'):
            qs = qs.filter(ou=self.cleaned_data['ou'])
        else:
            qs = self.filter_no_ou(qs)
        return qs


class RoleSearchForm(ServiceRoleSearchForm, OUSearchForm):
    ou_permission = 'a2_rbac.search_role'


class UserRoleSearchForm(OUSearchForm, ServiceRoleSearchForm):
    ou_permission = 'a2_rbac.change_role'

    def __init__(self, *args, **kwargs):
        # limit ou to target user ou
        request = kwargs['request']
        user = kwargs.pop('user')
        ou_qs = request.user.ous_with_perm(self.ou_permission).order_by('name')
        if user.ou_id:
            ou_qs = ou_qs.filter(id=user.ou_id)
        else:
            ou_qs = ou_qs.none()
        kwargs['ou_queryset'] = ou_qs
        super(UserRoleSearchForm, self).__init__(*args, **kwargs)

    def filter_no_ou(self, qs):
        return qs


class UserSearchForm(OUSearchForm, CssClass, PrefixFormMixin, FormWithRequest):
    ou_permission = 'custom_user.search_user'
    prefix = 'search'

    text = forms.CharField(
        label=_('Free text'),
        required=False)

    def filter(self, qs):
        qs = super(UserSearchForm, self).filter(qs)
        if self.cleaned_data.get('text'):
            qs = utils.filter_user(qs, self.cleaned_data['text'])
        return qs


class NameSearchForm(CssClass, PrefixFormMixin, FormWithRequest):
    prefix = 'search'

    text = forms.CharField(
        label=_('Name'),
        required=False)

    def filter(self, qs):
        if self.cleaned_data.get('text'):
            qs = qs.filter(name__icontains=self.cleaned_data['text'])
        return qs


class RoleEditForm(SlugMixin, HideOUFieldMixin, LimitQuerysetFormMixin, CssClass,
                   forms.ModelForm):
    ou = forms.ModelChoiceField(queryset=get_ou_model().objects,
                                required=True, label=_('Organizational unit'))

    def clean_name(self):
        qs = get_role_model().objects.all()
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        ou = self.cleaned_data.get('ou')
        # Test unicity of name for an OU and globally if no OU is present
        name = self.cleaned_data.get('name')
        if name and ou:
            query = Q(name=name) & (Q(ou__isnull=True) | Q(ou=ou))
            if qs.filter(query).exists():
                raise ValidationError(
                    {'name': _('This name is not unique over this organizational unit.')})
        return name

    class Meta:
        model = get_role_model()
        fields = ('name', 'ou', 'description')


class OUEditForm(SlugMixin, CssClass, forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(OUEditForm, self).__init__(*args, **kwargs)
        self.fields['name'].label = _('label').title()

    class Meta:
        model = get_ou_model()
        fields = ('name', 'default', 'username_is_unique', 'email_is_unique')


def get_role_form_class():
    if app_settings.ROLE_FORM_CLASS:
        return import_module_or_class(app_settings.ROLE_FORM_CLASS)
    return RoleEditForm
