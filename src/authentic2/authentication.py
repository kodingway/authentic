from authentic2_idp_oidc.models import OIDCClient

from rest_framework.authentication import BasicAuthentication


class OIDCUser(object):
    """ Fake user class to return in case OIDC authentication
    """

    def __init__(self, oidc_client):
        self.oidc_client = oidc_client
        self.authenticated = False

    def has_perm(self, *args, **kwargs):
        return True

    def has_perm_any(self, *args, **kwargs):
        return True

    def has_ou_perm(self, *args, **kwargs):
        return True

    def filter_by_perm(self, perms, queryset):
        return queryset

    def is_authenticated(self):
        return self.authenticated


class Authentic2Authentication(BasicAuthentication):

    def authenticate_credentials(self, userid, password):
        # try Simple OIDC Authentication
        try:
            client = OIDCClient.objects.get(client_id=userid, client_secret=password)
            user = OIDCUser(client)
            user.authenticated = True
            return (user, True)
        except OIDCClient.DoesNotExist:
            pass
        # try BasicAuthentication
        return super(Authentic2Authentication, self).authenticate_credentials(userid, password)
