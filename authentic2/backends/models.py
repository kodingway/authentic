from __future__ import unicode_literals
from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .. import app_settings

class ModelBackend(ModelBackend):
    """
    Authenticates against settings.AUTH_USER_MODEL.
    """

    def get_query(self, username):
        UserModel = get_user_model()
        username_field = UserModel.USERNAME_FIELD
        query = models.Q(**{username_field: username})
        try:
            if app_settings.ACCEPT_EMAIL_AUTHENTICATION and UserModel._meta.get_field('email'):
                query |= models.Q(**{'email': username})
        except models.FieldDoesNotExist:
            pass
        if '@' not in username:
            if app_settings.A2_REGISTRATION_REALM:
                u = u'{0}@{1}'.format(username, app_settings.A2_REGISTRATION_REALM)
                query |= models.Q(**{username_field: u})
            if app_settings.A2_REALMS:
                for realm in app_settings.A2_REALMS:
                    u = u'{0}@{1}'.format(username, realm)
                    query |= models.Q(**{username_field: u})
        return query

    def authenticate(self, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        query = self.get_query(username)
        for user in UserModel._default_manager.filter(query):
            if user.check_password(password):
                return user
