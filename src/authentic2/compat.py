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
