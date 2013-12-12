import string
import random
import logging
import lasso

from django.db import transaction
from django.core.urlresolvers import reverse
from django.utils.translation import ugettext as _

from authentic2.compat import get_user_model
from authentic2.saml.common import \
    lookup_federation_by_name_id_and_provider_id, add_federation, \
    get_idp_options_policy
from authentic2.saml.models import LIBERTY_SESSION_DUMP_KIND_SP, \
    LibertySessionDump, LibertyProvider
from authentic2.authsaml2.models import SAML2TransientUser

logger = logging.getLogger('authentic2.authsaml2.backends')


class AuthenticationError(Exception):
    pass


class AuthSAML2Backend:
    def logout_list(self, request):
        pid = None
        q = LibertySessionDump. \
            objects.filter(django_session_key=request.session.session_key,
                    kind=LIBERTY_SESSION_DUMP_KIND_SP)
        if not q:
            logger.debug('logout_list: no LibertySessionDump found')
            return []
        '''
            We deal with a single IdP session
        '''
        try:
            provider_id = lasso.Session(). \
                newFromDump(q[0].session_dump.encode('utf-8')). \
                    get_assertions().keys()[0]
        except:
            return []
        if not provider_id:
            return []
        logger.debug('logout_list: Found session for %s' % provider_id)
        name = provider_id
        provider = None
        try:
            provider = LibertyProvider.objects.get(entity_id=provider_id)
            name = provider.name
        except LibertyProvider.DoesNotExist:
            logger.error('logout_list: session found for unknown provider %s' \
                % provider_id)
            return []

        policy =  get_idp_options_policy(provider)
        if not policy:
            logger.error('logout_list: No policy found for %s' % provider_id)
            return []
        elif not policy.forward_slo:
            logger.info('logout_list: %s configured to not reveive slo' \
                % provider_id)
            return []
        else:
            import saml2_endpoints
            code = '<div>'
            code += _('Sending logout to %(pid)s....') % { 'pid': name or provider_id }
            code += '''<iframe src="%s?provider_id=%s" marginwidth="0" marginheight="0" \
    scrolling="no" style="border: none" width="16" height="16" onload="window.iframe_count -= 1; console.log('decrement iframe_count');"></iframe></div>''' \
                % (reverse(saml2_endpoints.sp_slo,
                    args=[provider_id]), provider_id)
            return [ code ]


class AuthSAML2PersistentBackend:
    supports_object_permissions = False
    supports_anonymous_user = False

    def authenticate(self, name_id=None, provider_id=None):
        '''Authenticate persistent NameID'''
        if not name_id or not provider_id:# or not name_id.nameQualifier:
            return None
        #fed = lookup_federation_by_name_identifier(name_id=name_id)
        fed = lookup_federation_by_name_id_and_provider_id(name_id, provider_id)
        if fed is None:
            return None
        fed.user.backend = '%s.%s' % (__name__, self.__class__.__name__)
        return fed.user

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

    @transaction.commit_on_success
    def create_user(self, username=None, name_id=None, provider_id=None):
        '''Create a new user mapping to the given NameID'''
        if not name_id or \
                 name_id.format != \
                 lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT or \
                 not name_id.nameQualifier:
            raise ValueError('Invalid NameID')
        if not username:
            # FIXME: maybe keep more information in the forged username
            username = 'saml2-%s' % ''. \
                join([random.SystemRandom().choice(string.letters) for x in range(10)])
        User = get_user_model()
        user = User()
        user.username = username
        if hasattr(User, 'set_unusable_password'):
            user.set_unusable_password()
        user.is_active = True
        user.save()
        add_federation(user, name_id=name_id, provider_id=provider_id)
        return user

class AuthSAML2TransientBackend:
    supports_object_permissions = False
    supports_anonymous_user = False

    def authenticate(self, name_id=None):
        '''Create temporary user for transient NameID'''
        if not name_id or \
                name_id.format != \
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT or \
                not name_id.content:
            return None
        user = SAML2TransientUser(id=name_id.content)
        return user

    def get_user(self, user_id):
        '''Create temporary user for transient NameID'''
        return SAML2TransientUser(id=user_id)
