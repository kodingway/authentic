from __future__ import unicode_literals

from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .. import app_settings

def upn(username, realm):
    '''Build an UPN from a username and a realm'''
    return u'{0}@{1}'.format(username, realm)

class ModelBackend(ModelBackend):
    """
    Authenticates against settings.AUTH_USER_MODEL.
    """

    def get_query(self, username, realm):
        UserModel = get_user_model()
        username_field = UserModel.USERNAME_FIELD
        queries = []
        try:
            if app_settings.ACCEPT_EMAIL_AUTHENTICATION \
                    and UserModel._meta.get_field('email'):
                queries.append(models.Q(**{'email': username}))
        except models.FieldDoesNotExist:
            pass

        if realm is None:
            queries.append(models.Q(**{username_field: username}))
            if '@' not in username:
                if app_settings.REALMS:
                    for realm, desc in app_settings.REALMS:
                        queries.append(models.Q(
                                **{username_field: upn(username, realm)}))
        else:
            queries.append(models.Q(**{username_field: upn(username, realm)}))
        return reduce(models.Q.__or__, queries)

    def authenticate(self, username=None, password=None, realm=None, **kwargs):
        UserModel = get_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        query = self.get_query(username, realm)
        for user in UserModel._default_manager.filter(query):
            if user.check_password(password):
                return user
