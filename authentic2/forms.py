from django import forms
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import get_user_model

from registration.forms import RegistrationForm

attrs_dict = { 'class': 'required' }

class AuthenticRegistrationForm(RegistrationForm):
    username = forms.RegexField(regex=r'^\w+$',
                                max_length=30,
                                widget=forms.TextInput(attrs=attrs_dict),
                                label=_(u'username'),
                                error_messages = {'invalid': _(u'your username must contain only letters, numbers and no spaces')})

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
                if field_name in get_user_model()._meta.get_all_field_names()]
