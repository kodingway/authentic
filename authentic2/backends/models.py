from __future__ import unicode_literals
from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .. import app_settings

class ModelBackend(ModelBackend):
    """
    Authenticates against settings.AUTH_USER_MODEL.
    """

    def authenticate(self, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        query = models.Q(**{UserModel.USERNAME_FIELD: username})
        try:
            if app_settings.ACCEPT_EMAIL_AUTHENTICATION and UserModel._meta.get_field('email'):
                query |= models.Q(**{'email': username})
        except models.FieldDoesNotExist:
            pass
        for user in UserModel._default_manager.filter(query):
            if user.check_password(password):
                return user
