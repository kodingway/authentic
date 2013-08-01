from django import forms


from django.contrib.auth.forms import UserChangeForm as AuthUserChangeForm, UserCreationForm as AuthUserCreationForm


from authentic2.compat import get_user_model


class UserChangeForm(AuthUserChangeForm):
    class Meta(AuthUserChangeForm.Meta):
        model = get_user_model()


class UserCreationForm(AuthUserCreationForm):
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
        raise forms.ValidationError(self.error_messages['duplicate_username'])
