from django.utils.translation import ugettext_lazy as _
from django import forms


from .. import app_settings, compat


class RegistrationForm(forms.Form):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    password1 = forms.CharField(widget=forms.PasswordInput,
                                label=_("Password"))
    password2 = forms.CharField(widget=forms.PasswordInput,
                                label=_("Password (again)"))

    def __init__(self, *args, **kwargs):
        """
        Inject required fields in registration form
        """
        super(RegistrationForm, self).__init__(*args, **kwargs)
        User = compat.get_user_model()
        insert_idx = 0
        field_names = compat.get_registration_fields()
        for field_name in field_names:
            if field_name not in self.fields:
                field = User._meta.get_field(field_name).formfield()
                self.fields.insert(insert_idx, field_name, field)
                insert_idx += 1
            self.fields[field_name].required = True
        if 'username' in self.fields:
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
