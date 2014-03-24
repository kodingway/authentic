from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.forms import Form, CharField, PasswordInput


from .. import app_settings, compat, forms


class RegistrationForm(forms.UserAttributeFormMixin, Form):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    password1 = CharField(widget=PasswordInput, label=_("Password"))
    password2 = CharField(widget=PasswordInput, label=_("Password (again)"))

    def __init__(self, *args, **kwargs):
        """
        Inject required fields in registration form
        """
        super(RegistrationForm, self).__init__(*args, **kwargs)
        User = compat.get_user_model()
        insert_idx = 0
        field_names = compat.get_registration_fields()
        required_fields = set(compat.get_required_fields())
        for field_name in field_names:
            if field_name not in self.fields:
                model_field = User._meta.get_field(field_name)
                kwargs = {}
                if hasattr(model_field, 'validators'):
                    kwargs['validators'] = model_field.validators
                field = model_field.formfield(**kwargs)
                self.fields.insert(insert_idx, field_name, field)
                insert_idx += 1
            if field_name in required_fields:
                self.fields[field_name].required = True
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
        existing = User.objects.filter(username__iexact=self.cleaned_data['username'])
        if existing.exists():
            raise ValidationError(_("A user with that username already exists."))
        else:
            return self.cleaned_data['username']

    def clean_email(self):
        """
        Verify if email is unique
        """
        User = compat.get_user_model()
        if app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE:
            if User.objects.filter(email__iexact=self.cleaned_data['email']):
                raise ValidationError(_('This email address is already in '
                    'use. Please supply a different email address.'))
        return self.cleaned_data['email']

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
