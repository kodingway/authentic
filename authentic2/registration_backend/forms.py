from uuid import uuid
import django

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.forms import Form, CharField, PasswordInput, EmailField
from django.utils.datastructures import SortedDict
from django.db.models import FieldDoesNotExist

from django.contrib.auth.models import BaseUserManager, Group
from django.contrib.auth import forms as auth_forms
from django.core.mail import send_mail
from django.core import signing
from django import get_version
from django.template.loader import render_to_string
from django.core.urlresolvers import reverse

from .. import app_settings, compat, forms, utils,\
    validators, widgets, fields, models

User = compat.get_user_model()

class RegistrationForm(Form):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    email = EmailField()

    def clean_email(self):
        """
        Verify if email is unique
        """
        User = compat.get_user_model()
        if app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE and \
           User.objects.filter(email__iexact=self.cleaned_data['email']).exists():
            raise ValidationError(_('This email address is already in '
                                    'use. Please supply a different email address.'))
        return self.cleaned_data['email']

    def save(self, request):
        data = self.cleaned_data
        data.update({'next_url': request.GET.get('next_url')})
        registration_token = signing.dumps(data)
        ctx_dict = {'registration_url': request.build_absolute_uri(
            reverse('registration_activate',
            kwargs={'registration_token': registration_token})),
                    'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
                    'email': data['email'],
                    'site': request.get_host()}
        ctx_dict.update(self.cleaned_data)

        subject = render_to_string('registration/activation_email_subject.txt',
                                   ctx_dict)

        subject = ''.join(subject.splitlines())
        message = render_to_string('registration/activation_email.txt',
                                   ctx_dict)
        if django.VERSION >= (1, 7, 0):
            html_message = render_to_string('registration/activation_email.html',
                                            ctx_dict)
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL,
                      [data['email']], fail_silently=True,
                      html_message=message)
        else:
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL,
                      [data['email']], fail_silently=True)

class RegistrationCompletionForm(forms.UserAttributeFormMixin, Form):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    password1 = CharField(widget=PasswordInput, label=_("Password"),
            validators=[validators.validate_password])
    password2 = CharField(widget=PasswordInput, label=_("Password (again)"))

    def __init__(self, *args, **kwargs):
        """
        Inject required fields in registration form
        """
        super(RegistrationCompletionForm, self).__init__(*args, **kwargs)
        User = compat.get_user_model()
        insert_idx = 0
        field_names = compat.get_registration_fields()
        required_fields = set(compat.get_required_fields())
        for field_name in field_names:
            if field_name not in self.fields:
                try:
                    model_field = User._meta.get_field(field_name)
                except FieldDoesNotExist:
                    pass
                else:
                    kwargs = {}
                    if hasattr(model_field, 'validators'):
                        kwargs['validators'] = model_field.validators
                    field = model_field.formfield(**kwargs)
                    if isinstance(field, EmailField):
                        continue
                    self.fields.insert(insert_idx, field_name, field)
                    insert_idx += 1
        for field_name in self.fields:
            if field_name in required_fields:
                self.fields[field_name].required = True
        # reorder fields obeying A2_REGISTRATION_FIELDS
        new_fields = SortedDict()
        for field_name in utils.field_names(app_settings.A2_REGISTRATION_FIELDS):
            if field_name in self.fields:
                new_fields[field_name] = self.fields[field_name]
        for field_name in self.fields:
            if field_name not in new_fields:
                new_fields[field_name] = self.fields[field_name]
        # override titles
        for field in app_settings.A2_REGISTRATION_FIELDS:
            if isinstance(field, (list, tuple)):
                if len(field) > 1:
                    self.fields[field[0]].label = field[1]

        self.fields = new_fields
        if 'username' in self.fields:
            self.fields['username'].regex = app_settings.A2_REGISTRATION_FORM_USERNAME_REGEX
            self.fields['username'].help_text = app_settings.A2_REGISTRATION_FORM_USERNAME_HELP_TEXT
            self.fields['username'].label = app_settings.A2_REGISTRATION_FORM_USERNAME_LABEL


    def clean_username(self):
        """
        Validate that the username is alphanumeric and is not already
        in use.
        """
        User = compat.get_user_model()
        username = self.cleaned_data['username']
        if app_settings.A2_REGISTRATION_REALM:
            if '@' in username:
                raise ValidationError(_('The character @ is forbidden in usernames.'))
            username = u'{0}@{1}'.format(username, app_settings.A2_REGISTRATION_REALM)
            self.cleaned_data['username'] = username
        existing = User.objects.filter(username__iexact=self.cleaned_data['username'])
        if existing.exists():
            raise ValidationError(_("A user with that username already exists."))
        else:
            return self.cleaned_data['username']

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
        return self.cleaned_data

    def save(self, *args, **kwargs):
        user_fields = {}
        for field in compat.get_registration_fields():
            # save User model fields
            try:
                User._meta.get_field(field)
            except FieldDoesNotExist:
                continue
            if field.startswith('password'):
                continue
            user_fields[field] = kwargs[field]
            if field == 'email':
                user_fields[field] = BaseUserManager.normalize_email(kwargs[field])

        new_user = User(is_active=True, **user_fields)
        new_user.clean()
        new_user.set_password(kwargs['password1'])
        new_user.save()

        if app_settings.A2_REGISTRATION_GROUPS:
            groups = []
            for name in app_settings.A2_REGISTRATION_GROUPS:
                group, created = Group.objects.get_or_create(name=name)
                groups.append(group)
            new_user.groups = groups
        return new_user, kwargs['next_url']

class SetPasswordForm(auth_forms.SetPasswordForm):
    new_password1 = CharField(label=_("New password"),
                                    widget=PasswordInput,
                                    validators=[validators.validate_password])

class PasswordChangeForm(auth_forms.PasswordChangeForm):
    new_password1 = CharField(label=_("New password"),
                                    widget=PasswordInput,
                                    validators=[validators.validate_password])


