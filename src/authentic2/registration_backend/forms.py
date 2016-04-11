import copy
from collections import OrderedDict

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _, ugettext
from django.forms import ModelForm, Form, CharField, PasswordInput, EmailField
from django.utils.datastructures import SortedDict
from django.db.models.fields import FieldDoesNotExist
from django.forms.util import ErrorList

from django.contrib.auth.models import BaseUserManager, Group
from django.contrib.auth import forms as auth_forms, get_user_model, REDIRECT_FIELD_NAME
from django.core.mail import send_mail
from django.core import signing
from django.template import RequestContext
from django.template.loader import render_to_string
from django.core.urlresolvers import reverse
from django.core.validators import RegexValidator

from .. import app_settings, compat, forms, utils, validators, models, middleware
from authentic2.a2_rbac.models import OrganizationalUnit

User = compat.get_user_model()

class RegistrationForm(Form):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    email = EmailField(label=_('Email'))

    def clean_email(self):
        """
        Verify if email is unique
        """
        User = compat.get_user_model()
        if (app_settings.A2_EMAIL_IS_UNIQUE or
               app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE) and \
               User.objects.filter(email__iexact=self.cleaned_data['email']).exists():
            raise ValidationError(_('This email address is already in '
                                    'use. Please supply a different email address.'))
        return self.cleaned_data['email']

    def save(self, request):
        data = self.cleaned_data
        token = request.GET.get('token', None)
        if token:
            token = signing.loads(token, max_age=settings.ACCOUNT_ACTIVATION_DAYS*3600*24)
            for name, value in token.items():
                data[name] = value
        if REDIRECT_FIELD_NAME in request.GET and REDIRECT_FIELD_NAME not in data:
            data[REDIRECT_FIELD_NAME] = request.GET[REDIRECT_FIELD_NAME]
        registration_token = signing.dumps(data)
        ctx_dict = RequestContext(request)
        ctx_dict.update({'registration_url': request.build_absolute_uri(
            reverse('registration_activate',
            kwargs={'registration_token': registration_token})),
                    'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
                    'email': data['email'],
                    'site': request.get_host()})
        ctx_dict.update(self.cleaned_data)

        subject = render_to_string('registration/activation_email_subject.txt',
                                   ctx_dict)

        subject = ''.join(subject.splitlines())
        message = render_to_string('registration/activation_email.txt',
                                   ctx_dict)

        html_message = render_to_string('registration/activation_email.html',
                                        ctx_dict)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL,
                  [data['email']], fail_silently=True,
                  html_message=html_message)


class RegistrationCompletionFormNoPassword(forms.BaseUserForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    def clean_username(self):
        if self.cleaned_data.get('username'):
            username = self.cleaned_data['username']
            username_is_unique = app_settings.A2_REGISTRATION_USERNAME_IS_UNIQUE
            if app_settings.A2_REGISTRATION_REALM:
                username += '@' + app_settings.A2_REGISTRATION_REALM
            if 'ou' in self.data:
                ou = OrganizationalUnit.objects.get(pk=self.data['ou'])
                username_is_unique |= ou.username_is_unique
            if username_is_unique:
                User = get_user_model()
                try:
                    User.objects.get(username=username)
                except User.DoesNotExist:
                    pass
                else:
                    raise ValidationError(_('This username is already in '
                                            'use. Please supply a different username.'))
            return username

    def clean_email(self):
        if self.cleaned_data.get('email'):
            email = self.cleaned_data['email']
            if app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE:
                User = get_user_model()
                try:
                    User.get(email__iexact=email)
                except User.DoesNotExist:
                    pass
                else:
                    raise ValidationError(_('This email address is already in '
                                            'use. Please supply a different email address.'))
            return BaseUserManager.normalize_email(email)

    def save(self, commit=True):
        user = super(RegistrationCompletionFormNoPassword, self).save(commit=commit)
        if commit and app_settings.A2_REGISTRATION_GROUPS:
            groups = []
            for name in app_settings.A2_REGISTRATION_GROUPS:
                group, created = Group.objects.get_or_create(name=name)
                groups.append(group)
            user.groups = groups
        return user


class RegistrationCompletionForm(RegistrationCompletionFormNoPassword):
    password1 = CharField(widget=PasswordInput, label=_("Password"),
            validators=[validators.validate_password],
            help_text=validators.password_help_text())
    password2 = CharField(widget=PasswordInput, label=_("Password (again)"))

    def clean(self):
        """
        Verifiy that the values entered into the two password fields
        match. Note that an error here will end up in
        ``non_field_errors()`` because it doesn't apply to a single
        field.
        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data:
            if self.cleaned_data['password1'] != self.cleaned_data['password2']:
                raise ValidationError(_("The two password fields didn't match."))
	    self.instance.set_password(self.cleaned_data['password1'])
        return self.cleaned_data


class PasswordResetMixin(Form):
    '''Remove all password reset object for the current user when password is
       successfully changed.'''

    def save(self, commit=True):
        ret = super(PasswordResetMixin, self).save(commit=commit)
        if commit:
            models.PasswordReset.objects.filter(user=self.user).delete()
        else:
            old_save = self.user.save
            def save(*args, **kwargs):
                ret = old_save(*args, **kwargs)
                models.PasswordReset.objects.filter(user=self.user).delete()
                return ret
            self.user.save = save
        return ret


class NotifyOfPasswordChange(object):
    def save(self, commit=True):
        user = super(NotifyOfPasswordChange, self).save(commit=commit)
        if user.email:
            ctx = {
                'user': user,
                'password': self.cleaned_data['new_password1'],
            }
            utils.send_templated_mail(user, "authentic2/password_change", ctx)
        return user


class SetPasswordForm(NotifyOfPasswordChange, PasswordResetMixin, auth_forms.SetPasswordForm):
    new_password1 = CharField(label=_("New password"),
                                    widget=PasswordInput,
                                    validators=[validators.validate_password],
                                    help_text=validators.password_help_text())

    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1')
        if new_password1 and self.user.check_password(new_password1):
            raise ValidationError(_('New password must differ from old password'))
        return new_password1


class PasswordChangeForm(NotifyOfPasswordChange, forms.NextUrlFormMixin, PasswordResetMixin,
                         auth_forms.PasswordChangeForm):
    new_password1 = CharField(label=_("New password"),
                                    widget=PasswordInput,
                                    validators=[validators.validate_password],
                                    help_text=validators.password_help_text())

    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1')
        old_password = self.cleaned_data.get('old_password')
        if new_password1 and new_password1 == old_password:
            raise ValidationError(_('New password must differ from old password'))
        return new_password1

# make old_password the first field
PasswordChangeForm.base_fields = OrderedDict(
    [(k, PasswordChangeForm.base_fields[k])
    for k in ['old_password', 'new_password1', 'new_password2']] +
    [(k, PasswordChangeForm.base_fields[k])
    for k in PasswordChangeForm.base_fields if k not in ['old_password', 'new_password1',
                                                         'new_password2']]
)

class DeleteAccountForm(Form):
    password = CharField(widget=PasswordInput, label=_("Password"))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super(DeleteAccountForm, self).__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if password and not self.user.check_password(password):
            raise ValidationError(ugettext('Password is invalid'))
        return password
