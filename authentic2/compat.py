from django.conf import settings

try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User
    get_user_model = lambda: User

user_model_label = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')

use_attribute_aggregator = 'authentic2.attribute_aggregator' \
        in settings.INSTALLED_APPS
