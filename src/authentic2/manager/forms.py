from django.utils.translation import ugettext_lazy as _
from django import forms
from django.contrib.contenttypes.models import ContentType
from django.db.models.query import Q

from authentic2.compat import get_user_model
from authentic2.passwords import generate_password
from authentic2.utils import send_templated_mail
from authentic2.models import Service

from django_rbac.models import Operation
from django_rbac.utils import get_ou_model, get_role_model

from authentic2.forms import BaseUserForm
from authentic2.models import PasswordReset

from . import fields


class CssClass(object):
    error_css_class = 'error'
    required_css_class = 'required'


class PrefixFormMixin(object):
    def __init__(self, *args, **kwargs):
        kwargs['prefix'] = self.__class__.prefix
        super(PrefixFormMixin, self).__init__(*args, **kwargs)


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


class ChooseUserRoleForm(CssClass, forms.Form):
    role = fields.ChooseUserRoleField(label=_('Add a role'))
    action = forms.CharField(initial='add', widget=forms.HiddenInput)


class ChoosePermissionForm(CssClass, forms.Form):
    operation = forms.ModelChoiceField(
        label=_('Operation'),
        queryset=Operation.objects)
    ou = forms.ModelChoiceField(
        label=_('Organizational unit'),
        queryset=get_ou_model().objects,
        required=False)
    target = forms.ModelChoiceField(
        label=_('Target object'),
        queryset=ContentType.objects)
    action = forms.CharField(
        initial='add',
        widget=forms.HiddenInput)


class UserEditForm(LimitQuerysetFormMixin, CssClass, BaseUserForm):
    css_class = "user-form"
    form_id = "id_user_edit_form"

    ou = forms.ModelChoiceField(queryset=get_ou_model().objects,
                                required=True, label=_('Organizational unit'))

    def __init__(self, *args, **kwargs):
        super(UserEditForm, self).__init__(*args, **kwargs)
        if not self.request.user.is_superuser and \
           'is_superuser' in self.fields:
            del self.fields['is_superuser']

    def clean(self):
        if not self.cleaned_data.get('username') and \
           not self.cleaned_data.get('email'):
            raise forms.ValidationError(
                _('You must set a username or an email.'))

    class Meta:
        model = get_user_model()
        exclude = ('is_staff', 'groups', 'user_permissions', 'last_login',
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
        if self.instance and self.instance.pk \
           and not self.instance.email and \
           (self.cleaned_data.get('send_mail') or
            self.cleaned_data.get('generate_password')):
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
        if self.cleaned_data['generate_password'] \
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

    def clean(self):
        super(UserAddForm, self).clean()
        if not self.cleaned_data.get('username') and \
           not self.cleaned_data.get('email'):
            raise forms.ValidationError(
                _('You must set a username or an email.'))

    def save(self, commit=True):
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


class ServiceRoleSearchForm(CssClass, PrefixFormMixin, forms.Form):
    prefix = 'search'

    text = forms.CharField(
        label=_('Name'),
        required=False)

    def filter(self, qs):
        if self.cleaned_data.get('text'):
            qs = qs.filter(name__icontains=self.cleaned_data['text'])
        return qs


class RoleSearchForm(ServiceRoleSearchForm):
    ou = forms.ModelChoiceField(queryset=get_ou_model().objects,
                                required=False, label=_('Organizational unit'))
    service = forms.ModelChoiceField(
        queryset=Service.objects,
        label=_('Service'),
        required=False)

    def filter(self, qs):
        qs = super(RoleSearchForm, self).filter(qs)
        if self.cleaned_data.get('ou'):
            qs = qs.filter(ou=self.cleaned_data['ou'])
        if self.cleaned_data.get('service'):
            qs = qs.filter(service=self.cleaned_data['service'])
        return qs


class UserSearchForm(CssClass, PrefixFormMixin, forms.Form):
    prefix = 'search'

    text = forms.CharField(
        label=_('Name'),
        required=False)
    ou = forms.ModelChoiceField(
        queryset=get_ou_model().objects,
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
    ou = forms.ModelChoiceField(queryset=get_ou_model().objects,
                                required=True, label=_('Organizational unit'))

    class Meta:
        model = get_role_model()
        fields = ('name', 'slug', 'ou', 'description')


class OUEditForm(CssClass, forms.ModelForm):
    class Meta:
        model = get_ou_model()
        fields = ('name', 'slug', 'default')
