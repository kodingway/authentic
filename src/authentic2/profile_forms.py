
from django import forms
from django.utils.translation import ugettext as _
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator

from .utils import send_password_reset_mail


class PasswordResetForm(forms.Form):
    email = forms.EmailField(
        label=_("Email"), max_length=254)

    def save(self):
        """
        Generates a one-use only link for resetting password and sends to the
        user.
        """
        UserModel = get_user_model()
        email = self.cleaned_data["email"]
        active_users = UserModel._default_manager.filter(
            email__iexact=email, is_active=True)
        for user in active_users:
            send_password_reset_mail(user)
