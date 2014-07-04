from django.conf import settings

try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User
    get_user_model = lambda: User

from . import app_settings

user_model_label = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')

use_attribute_aggregator = 'authentic2.attribute_aggregator' \
        in settings.INSTALLED_APPS

def get_registration_fields():
    """
    Return the list of fields to show on registration page
    """
    User = get_user_model()
    username_field = getattr(User, 'USERNAME_FIELD', 'username')
    field_names = getattr(User, 'REGISTER_FIELDS', get_required_fields())
    setting_fields = app_settings.A2_REGISTRATION_FIELDS
    return [username_field] + list(field_names) + list(setting_fields)

def get_required_fields():
    """
    Return the list of fields to show on registration page
    """
    User = get_user_model()
    username_field = getattr(User, 'USERNAME_FIELD', 'username')
    field_names = getattr(User, 'REQUIRED_FIELDS', [])
    setting_fields = app_settings.A2_REGISTRATION_REQUIRED_FIELDS
    return [username_field] + list(field_names) + list(setting_fields)
