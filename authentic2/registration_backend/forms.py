from django.utils.translation import ugettext_lazy as _
from django import forms


from registration.forms import RegistrationForm as BaseRegistrationForm


from .. import app_settings, compat


class RegistrationForm(BaseRegistrationForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'


    def __init__(self, *args, **kwargs):
        """
        Inject required fields in registration form
        """
        super(RegistrationForm, self).__init__(*args, **kwargs)
        insert_idx = 1
        User = compat.get_user_model()
        for field_name in User.REQUIRED_FIELDS:
            if field_name not in self.fields:
                field = User._meta.get_field(field_name).formfield()
                self.fields.insert(insert_idx, field_name, field)
                insert_idx += 1
            self.fields[field_name].required = True
        self.fields['username'].regex = app_settings.A2_REGISTRATION_FORM_USERNAME_REGEX
        self.fields['username'].help_text = app_settings.A2_REGISTRATION_FORM_USERNAME_HELP_TEXT
        self.fields['username'].label = app_settings.A2_REGISTRATION_FORM_USERNAME_LABEL


    def clean_email(self):
        """
        Verify if email is unique
        """
        User = compat.get_user_model()
        if app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE:
            if User.objects.filter(email__iexact=self.cleaned_data['email']):
                raise forms.ValidationError(_('This email address is already in '
                    'use. Please supply a different email address.'))
        return self.cleaned_data['email']

    def clean_username(self):
        """
        Validate that the username is alphanumeric and is not already
        in use.

        """
        existing = compat.get_user_model().objects.filter(username__iexact=self.cleaned_data['username'])
        if existing.exists():
            raise forms.ValidationError(_("A user with that username already exists."))
        else:
            return self.cleaned_data['username']
