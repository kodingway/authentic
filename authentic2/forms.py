from django import forms
from django.contrib.auth import models as auth_models

from authentic2.compat import get_user_model

auth_models.User.USER_PROFILE = ('first_name', 'last_name', 'email')
User = get_user_model()
all_field_names = [field.name for field in User._meta.fields]
field_names = getattr(User, 'USER_PROFILE', all_field_names)


class UserProfileForm(forms.ModelForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super(UserProfileForm, self).__init__(**kwargs)
        for field in get_user_model().REQUIRED_FIELDS:
            if field in self.fields:
                self.fields[field].required = True

    def save(self, commit=True):
        instance = super(UserProfileForm, self).save(commit=False)
        instance.user = self.user
        if commit:
            instance.save()
        return instance

    class Meta:
        model = User
        fields = [ field_name
                for field_name in field_names
                if field_name in all_field_names
                    and field_name != model.USERNAME_FIELD
                    and field_name != 'email' ]
