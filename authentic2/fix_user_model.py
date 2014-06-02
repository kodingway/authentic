# Patch base usermodel username max_lenght
from django.utils.translation import ugettext_lazy as _
from django.core.validators import MaxLengthValidator
from django.db.models.signals import class_prepared
from django.db.models import FieldDoesNotExist

from . import validators

MAX_USERNAME_LENGTH = 255

def longer_username_signal(sender, *args, **kwargs):
    if (sender.__name__ == "User" and
        sender.__module__ == "django.contrib.auth.models"):
        patch_user_model(sender)
class_prepared.connect(longer_username_signal)

def patch_user_model(model):
    patch_username(model)
    patch_email(model)

def patch_username(model):
    try:
        field = model._meta.get_field("username")
    except FieldDoesNotExist:
        return

    field.max_length = MAX_USERNAME_LENGTH
    field.help_text = _("Required, %s characters or fewer. Only letters, "
                        "numbers, and @, ., +, -, or _ "
                        "characters." % MAX_USERNAME_LENGTH)

    # patch model field validator because validator doesn't change if we change
    # max_length
    for v in field.validators:
        if isinstance(v, MaxLengthValidator):
            v.limit_value = MAX_USERNAME_LENGTH

def patch_email(model):
    try:
        field = model._meta.get_field("email")
    except FieldDoesNotExist:
        return

    field.validators.append(validators.EmailValidator())