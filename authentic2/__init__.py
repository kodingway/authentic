import sys
import os

__version__ = "2.1.2"

# vendor contains incorporated dependencies
sys.path.append(os.path.join(os.path.dirname(__file__), 'vendor'))


# Patch base usermodel username max_lenght
from django.utils.translation import ugettext_lazy as _
from django.core.validators import MaxLengthValidator
from django.db.models.signals import class_prepared

MAX_USERNAME_LENGTH = 255

def longer_username_signal(sender, *args, **kwargs):
    if (sender.__name__ == "User" and
        sender.__module__ == "django.contrib.auth.models"):
        patch_user_model(sender)
class_prepared.connect(longer_username_signal)

def patch_user_model(model):
    field = model._meta.get_field("username")

    field.max_length = MAX_USERNAME_LENGTH
    field.help_text = _("Required, %s characters or fewer. Only letters, "
                        "numbers, and @, ., +, -, or _ "
                        "characters." % MAX_USERNAME_LENGTH)

    # patch model field validator because validator doesn't change if we change
    # max_length
    for v in field.validators:
        if isinstance(v, MaxLengthValidator):
            v.limit_value = MAX_USERNAME_LENGTH
