import re

from django.utils.translation import ugettext_lazy as _
from django.core.validators import MaxLengthValidator, RegexValidator
from django.db.models.signals import class_prepared
from django.db.models import FieldDoesNotExist
from django.contrib.auth import forms
from django.contrib.auth import get_user_model

from . import validators, app_settings, admin_forms

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
    '''Patch username max_length,  validation regexp and help text'''
    try:
        field = model._meta.get_field("username")
    except FieldDoesNotExist:
        return

    field.max_length = MAX_USERNAME_LENGTH
    field.help_text = _("Required, %s characters or fewer. Only letters, "
                        "numbers, and @, ., +, -, or _ "
                        "characters." % MAX_USERNAME_LENGTH)
    if app_settings.A2_USERNAME_HELP_TEXT:
        field.help_text = app_settings.A2_USERNAME_HELP_TEXT
    field.label = _('username')

    # patch model field validator because validator doesn't change if we change
    # max_length
    if app_settings.A2_USERNAME_REGEX:
        r =  re.compile(app_settings.A2_USERNAME_REGEX, re.UNICODE)
    for v in field.validators:
        if isinstance(v, MaxLengthValidator):
            v.limit_value = MAX_USERNAME_LENGTH
        if isinstance(v, RegexValidator):
            if app_settings.A2_USERNAME_REGEX:
                v.regex = r
    for form in (forms.UserChangeForm, forms.UserCreationForm,
            admin_forms.UserChangeForm, admin_forms.UserCreationForm):
        field = form.base_fields['username']
        if app_settings.A2_USERNAME_REGEX:
            field.regex = r
        field.max_length = MAX_USERNAME_LENGTH
        field.widget.attrs[u'maxlength'] = MAX_USERNAME_LENGTH
        if app_settings.A2_USERNAME_HELP_TEXT:
            field.help_text = app_settings.A2_USERNAME_HELP_TEXT
        for v in field.validators:
            if isinstance(v, MaxLengthValidator):
                v.limit_value = MAX_USERNAME_LENGTH
            if isinstance(v, RegexValidator):
                if app_settings.A2_USERNAME_REGEX:
                    v.regex = r

def patch_email(model):
    try:
        field = model._meta.get_field("email")
    except FieldDoesNotExist:
        return
    patch_validators(field)
    from django.db.models.fields import EmailField
    EmailField.default_validators = [validators.EmailValidator()]
    from django.forms import EmailField
    EmailField.default_validators = [validators.EmailValidator()]


def patch_validators(field):
    field.validators = list(field.validators)
    for i, validator in tuple(enumerate(field.validators)):
        if validator.__class__.__name__.startswith('Email'):
            field.validators.pop(i)
    field.validators.append(validators.EmailValidator())
    field.validators = []
    field.__class__.default_validators = []

patch_user_model(get_user_model())
