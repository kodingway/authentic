from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import get_user_model
from django import forms


from registration.forms import RegistrationForm as BaseRegistrationForm


class RegistrationForm(BaseRegistrationForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'


    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        for field in get_user_model().REQUIRED_FIELDS:
            self.fields[field].required = True

    def clean_username(self):
        """
        Validate that the username is alphanumeric and is not already
        in use.

        """
        existing = get_user_model().objects.filter(username__iexact=self.cleaned_data['username'])
        if existing.exists():
            raise forms.ValidationError(_("A user with that username already exists."))
        else:
            return self.cleaned_data['username']
