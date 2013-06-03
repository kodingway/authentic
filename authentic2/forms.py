from django import forms
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import get_user_model

from registration.forms import RegistrationForm

attrs_dict = { 'class': 'required' }

class AuthenticRegistrationForm(RegistrationForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'


    def __init__(self, *args, **kwargs):
        super(AuthenticRegistrationForm, self).__init__(*args, **kwargs)
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

class UserProfileForm(forms.ModelForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super(UserProfileForm, self).__init__(**kwargs)
        for field in get_user_model().REQUIRED_FIELDS:
            self.fields[field].required = True

    def save(self, commit=True):
        instance = super(UserProfileForm, self).save(commit=False)
        instance.user = self.user
        if commit:
            instance.save()
        return instance

    class Meta:
        model = get_user_model()
        fields = [ field_name
                for field_name in get_user_model().USER_PROFILE
                if field_name in get_user_model()._meta.get_all_field_names()
                    and not field_name == get_user_model().USERNAME_FIELD ]
