import django

from django.conf import settings

try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User
    get_user_model = lambda: User

try:
    from django.db.transaction import atomic
    commit_on_success = atomic
except ImportError:
    from django.db.transaction import commit_on_success

from . import app_settings, utils

user_model_label = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')

from django.contrib.auth.tokens import PasswordResetTokenGenerator
if django.VERSION < (1, 8):
    class PasswordResetTokenGenerator(PasswordResetTokenGenerator):
        def check_token(self, user, token):
            if not user.last_login:
                new_user = user.__class__()
                new_user.__dict__ = user.__dict__
                new_user.last_login = new_user.last_login or ''
                user = new_user
            return super(PasswordResetTokenGenerator, self).check_token(user, token)

        def make_token(self, user):
            if not user.last_login:
                new_user = user.__class__()
                new_user.__dict__ = user.__dict__
                usre = new_user
            return super(PasswordResetTokenGenerator, self).make_token(user)

default_token_generator = PasswordResetTokenGenerator()
