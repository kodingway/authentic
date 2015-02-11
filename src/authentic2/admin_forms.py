from django.core.exceptions import ValidationError
from django.contrib.auth.forms import (UserChangeForm as
        AuthUserChangeForm, UserCreationForm as
        AuthUserCreationForm)

from authentic2.compat import get_user_model

from . import forms

class UserChangeForm(forms.UserAttributeFormMixin,
        AuthUserChangeForm):

    class Meta(AuthUserChangeForm.Meta):
        model = get_user_model()

class UserCreationForm(forms.UserAttributeFormMixin,
        AuthUserCreationForm):

    class Meta(AuthUserCreationForm.Meta):
        model = get_user_model()

    def clean_username(self):
        # Since User.username is unique, this check is redundant,
        # but it sets a nicer error message than the ORM. See #13147.
        username = self.cleaned_data["username"]
        User = get_user_model()
        try:
            User._default_manager.get(username=username)
        except User.DoesNotExist:
            return username
        raise ValidationError(self.error_messages['duplicate_username'])

from . import fix_user_model
fix_user_model.patch_forms((UserChangeForm, UserCreationForm))
fix_user_model.patch_forms((AuthUserChangeForm, AuthUserCreationForm))
