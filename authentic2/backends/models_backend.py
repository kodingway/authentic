from __future__ import unicode_literals

from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .. import app_settings
from authentic2.user_login_failure import user_login_success, user_login_failure

def upn(username, realm):
    '''Build an UPN from a username and a realm'''
    return u'{0}@{1}'.format(username, realm)

PROXY_USER_MODEL = None

def get_proxy_user_model():
    global PROXY_USER_MODEL
    if PROXY_USER_MODEL is None:
        class ProxyUser(get_user_model()):
            def roles(self):
                return self.groups.values_list('name', flat=True)

            class Meta:
                proxy = True
        PROXY_USER_MODEL = ProxyUser
    return PROXY_USER_MODEL

class ModelBackend(ModelBackend):
    """
    Authenticates against settings.AUTH_USER_MODEL.
    """

    def get_query(self, username, realm):
        UserModel = get_proxy_user_model()
        username_field = UserModel.USERNAME_FIELD
        queries = []
        try:
            if app_settings.ACCEPT_EMAIL_AUTHENTICATION \
                    and UserModel._meta.get_field('email'):
                queries.append(models.Q(**{'email__iexact': username}))
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

    def must_reset_password(self, user):
        from .. import models
        return bool(models.PasswordReset.filter(user=user).count())

    def authenticate(self, username=None, password=None, realm=None, **kwargs):
        UserModel = get_proxy_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        if not username:
            return
        query = self.get_query(username, realm)
        users = UserModel.objects.filter(query)
        # order by username to make username without realm come before usernames with realms
        # i.e. "toto" should come before "toto@example.com"
        users = users.order_by(UserModel.USERNAME_FIELD)
        for user in users:
            if user.check_password(password):
                user_login_success(user.get_username())
                return user
            else:
                user_login_failure(user.get_username())
