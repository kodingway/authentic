from django.db.models import Q
from django.db import transaction
import logging

from authentic2.compat import get_user_model

from . import models, app_settings

class AuthenticationError(Exception):
    pass

class SSLBackend:
    """
    authenticates a client certificate against the records stored 
    in ClientCertificate model and looks up the corresponding django user

    In all methods, the ssl_info parameter is supposed to be an SSLInfo
    instance
    """
    supports_object_permissions = False
    supports_anonymous_user = False

    def authenticate(self, ssl_info):
        cert = self.get_certificate(ssl_info)
        if cert is None:
            return None
        else:
            return cert.user

    def get_user(self, user_id):
        """
        simply return the user object. That way, we only need top look-up the
        certificate once, when loggin in
        """
        User = get_user_model()
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

    def get_certificate(self, ssl_info):
        """
        returns a ClientCertificate object for the passed
        cert data or None if not found
        """

        if app_settings.STRICT_MATCH:
            # compare complete certificate in strict match
            if not ssl_info.cert:
                logging.error('SSLAuth: strict match required but PEM encoded \
certificate not found in environment. Check your server \
settings')
                return None
            query = Q(cert=ssl_info.cert)
        else:
            query_args = {}
            for key in app_settings.SUBJECT_MATCH_KEYS:
                if not ssl_info.get(key):
                    logging.error('SSLAuth: key %s is missing from ssl_info' \
                        % key)
                    return None
                query_args[key] = ssl_info.get(key)

            query = Q(**query_args)
        try:
            cert = models.ClientCertificate.objects.select_related().get(query)
            return cert
        except models.ClientCertificate.DoesNotExist:
            return None


    @transaction.commit_on_success
    def create_user(self, ssl_info):
        """
        This method creates a new django User and ClientCertificate record
        for the passed certificate info. It does not create an issuer record,
        just a subject for the ClientCertificate.
        """
        # auto creation only created a DN for the subject, not the issuer
        User = get_user_model()

        # get username and check if the user exists already
        if app_settings.CREATE_USERNAME_CALLBACK:
            build_username = app_settings.CEATE_USERNAME_CALLBACK
        else:
            build_username = self.build_username

        username = build_username(ssl_info)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            if app_settings.CREATE_USER_CALLBACK:
                build_user = app_settings.CREATE_USER_CALLBACK
            else:
                build_user = self.build_user
            user = build_user(username, ssl_info)

        # create the certificate record and save
        self.link_user(ssl_info, user)
        return user

    @transaction.commit_on_success
    def link_user(self, ssl_info, user):
        """
        This method creates a new django User and ClientCertificate record
        for the passed certificate info. It does not create an issuer record,
        just a subject for the ClientCertificate.
        """
        # create the certificate record and save
        cert = models.ClientCertificate()
        cert.user = user
        cert.subject_dn = ssl_info.subject_dn
        cert.issuer_dn = ssl_info.issuer_dn
        cert.serial = ssl_info.serial
        cert.cert = ssl_info.cert
        cert.save()

        return user


    def build_user(self, username, ssl_info):
        """
        create a valid (and stored) django user to be associated with the
        newly created certificate record. This method can be "overwritten" by
        using the SSLAUTH_CREATE_USER_CALLBACK setting.
        """
        User = get_user_model()
        user = User()
        setattr(user, User.USERNAME_FIELD, username)
        if hasattr(User, 'set_unusable_password'):
            user.set_unusable_password()
        user.is_active = True
        user.save()
        return user

    @classmethod
    def get_saml2_authn_context(cls):
        import lasso
        return lasso.SAML2_AUTHN_CONTEXT_X509
