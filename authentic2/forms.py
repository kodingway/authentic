from django import forms
from django.utils.translation import ugettext_lazy as _

from registration.forms import RegistrationForm

from authentic2.idp.models import UserProfile

attrs_dict = { 'class': 'required' }

class AuthenticRegistrationForm(RegistrationForm):
    username = forms.RegexField(regex=r'^\w+$',
                                max_length=30,
                                widget=forms.TextInput(attrs=attrs_dict),
                                label=_(u'username'),
                                error_messages = {'invalid': _(u'your username must contain only letters, numbers and no spaces')})

class UserProfileForm(forms.ModelForm):
    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super(UserProfileForm, self).__init__(**kwargs)

    def save(self, commit=True):
        instance = super(UserProfileForm, self).save(commit=False)
        instance.user = self.user
        if commit:
            instance.save()
        return instance

    class Meta:
        exclude = ('user',)
        model = UserProfile
