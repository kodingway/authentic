"""SAML2.0 IdP implementation

   It contains endpoints to receive:
    - authentication requests,
    - logout request,
    - logout response,
    - name id management requests,
    - name id management responses,
    - attribut requests.
    - logout
    - logoutResponse

    TODO:
     - manageNameId
     - manageNameIdResponse
     - assertionIDRequest
"""

import datetime
import logging
import urllib
import xml.etree.cElementTree as ctree
import hashlib
import random
import string

import lasso
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse, HttpResponseRedirect, \
    HttpResponseForbidden, HttpResponseBadRequest, Http404
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import BACKEND_SESSION_KEY
from django.conf import settings
from django.utils.encoding import smart_unicode
from django.contrib.auth import load_backend


from authentic2.idp.utils import get_username
from authentic2.compat import get_user_model
import authentic2.idp as idp
import authentic2.idp.views as idp_views
from authentic2.idp.models import get_attribute_policy
from authentic2.saml.models import LibertyAssertion, LibertyArtifact, \
    LibertySession, LibertyFederation, LibertySessionDump, \
    nameid2kwargs, saml2_urn_to_nidformat, LIBERTY_SESSION_DUMP_KIND_SP, \
    nidformat_to_saml2_urn, save_key_values, get_and_delete_key_values, \
    LibertyProvider, LibertyServiceProvider, NAME_ID_FORMATS
from authentic2.saml.common import redirect_next, asynchronous_bindings, \
    soap_bindings, load_provider, get_saml2_request_message, \
    error_page, set_saml2_response_responder_status_code, \
    AUTHENTIC_STATUS_CODE_MISSING_DESTINATION, \
    load_federation, load_session, \
    return_saml2_response, save_session, \
    get_soap_message, soap_fault, return_saml_soap_response, \
    AUTHENTIC_STATUS_CODE_UNKNOWN_PROVIDER, \
    AUTHENTIC_STATUS_CODE_MISSING_NAMEID, \
    AUTHENTIC_STATUS_CODE_MISSING_SESSION_INDEX, \
    AUTHENTIC_STATUS_CODE_UNKNOWN_SESSION, \
    AUTHENTIC_STATUS_CODE_INTERNAL_SERVER_ERROR, \
    AUTHENTIC_STATUS_CODE_UNAUTHORIZED, \
    send_soap_request, get_saml2_query_request, \
    get_saml2_request_message_async_binding, create_saml2_server, \
    get_saml2_metadata, get_sp_options_policy, get_idp_options_policy, \
    get_entity_id
import authentic2.saml.saml2utils as saml2utils
from authentic2.auth2_auth.models import AuthenticationEvent
from common import redirect_to_login, kill_django_sessions
from authentic2.auth2_auth import NONCE_FIELD_NAME
from authentic2.idp.interactions import consent_federation, consent_attributes

from authentic2.idp import signals as idp_signals
# from authentic2.idp.models import *

from authentic2.authsaml2.models import SAML2TransientUser
from authentic2.utils import cache_and_validate

logger = logging.getLogger('authentic2.idp.saml')

def get_nonce():
    alphabet = string.letters+string.digits
    return '_'+''.join(random.SystemRandom().choice(alphabet) for i in xrange(20))

metadata_map = (
        (saml2utils.Saml2Metadata.SINGLE_SIGN_ON_SERVICE,
            asynchronous_bindings, '/sso'),
        (saml2utils.Saml2Metadata.SINGLE_LOGOUT_SERVICE,
            asynchronous_bindings, '/slo', '/slo_return'),
        (saml2utils.Saml2Metadata.SINGLE_LOGOUT_SERVICE,
            soap_bindings, '/slo/soap'),
        (saml2utils.Saml2Metadata.ARTIFACT_RESOLUTION_SERVICE,
            lasso.SAML2_METADATA_BINDING_SOAP, '/artifact')
)
metadata_options = {'key': settings.SAML_SIGNATURE_PUBLIC_KEY}


@cache_and_validate(settings.LOCAL_METADATA_CACHE_TIMEOUT)
def metadata(request):
    '''Endpoint to retrieve the metadata file'''
    logger.info('return metadata')
    return HttpResponse(get_metadata(request, request.path),
            mimetype='text/xml')


#####
# SSO
#####
def register_new_saml2_session(request, login, federation=None):
    '''Persist the newly created session for emitted assertion'''
    logger.info("assertion and saml session "
        "registration")
    lib_assertion = LibertyAssertion(saml2_assertion=login.assertion)
    lib_assertion.save()
    logger.debug('assertion saved')
    lib_session = LibertySession(provider_id=login.remoteProviderId,
            saml2_assertion=login.assertion, federation=federation,
            django_session_key=request.session.session_key,
            assertion=lib_assertion)
    lib_session.save()
    logger.debug('session saved')


def fill_assertion(request, saml_request, assertion, provider_id, nid_format):
    '''Stuff an assertion with information extracted from the user record
       and from the session, and eventually from transactions linked to the
       request, i.e. a login event or a consent event.

       No check on the request must be done here, the sso method should have
       verified that the request can be answered and match any policy for the
       given provider or modified the request to match the identity provider
       policy.

    TODO: add attributes from user account
    TODO: determine and add attributes from the session, for anonymous users
    (pseudonymous federation, openid without accounts)
    # TODO: add information from the login event, of the session or linked
    # to the request id
    # TODO: use information from the consent event to specialize release of
    # attributes (user only authorized to give its email for email)
       '''
    assert nid_format in NAME_ID_FORMATS

    logger.debug('initializing assertion %r', assertion.id)
    # Use assertion ID as session index
    assertion.authnStatement[0].sessionIndex = assertion.id
    logger.debug("nid_format is %r", nid_format)
    if nid_format == 'transient':
        # Generate the transient identifier from the session key, to fix it for
        # a session duration, without that logout is broken as you can send
        # many session_index in a logout request but only one NameID
        keys = ''.join([request.session.session_key, provider_id,
            settings.SECRET_KEY])
        transient_id_content = '_' + hashlib.sha1(keys).hexdigest().upper()
        assertion.subject.nameID.content = transient_id_content
    if nid_format == 'email':
        assert request.user.email, 'email is required when using the email NameID format'
        assertion.subject.nameID.content = request.user.email
    if nid_format == 'username':
        username = get_username(request.user)
        assert username, 'username is required when using the username NameID format'
        assertion.subject.nameID.content = username
    if nid_format == 'edupersontargetedid':
        assertion.subject.nameID.format = NAME_ID_FORMATS[nid_format]['samlv2']
        keys = ''.join([get_username(request.user),
            provider_id, settings.SECRET_KEY])
        edu_person_targeted_id = '_' + hashlib.sha1(keys).hexdigest().upper()
        assertion.subject.nameID.content = edu_person_targeted_id
        attribute_definition = ('urn:oid:1.3.6.1.4.1.5923.1.1.1.10',
                lasso.SAML2_ATTRIBUTE_NAME_FORMAT_URI, 'eduPersonTargetedID')
        value = assertion.subject.nameID.exportToXml()
        value = ctree.fromstring(value)
        saml2_add_attribute_values(assertion,
                { attribute_definition: [ value ]})
        logger.info('adding an eduPersonTargetedID attribute with value %s',
                edu_person_targeted_id)
    assertion.subject.nameID.format = NAME_ID_FORMATS[nid_format]['samlv2']


def saml2_add_attribute_values(assertion, attributes):
    if not attributes:
        logger.info("\
            there are no attributes to add")
    else:
        logger.info("there are attributes to add")
        logger.debug("\
            assertion before processing %s" % assertion.dump())
        logger.debug("adding attributes %s" \
            % str(attributes))
        if not assertion.attributeStatement:
            assertion.attributeStatement = [lasso.Saml2AttributeStatement()]
        attribute_statement = assertion.attributeStatement[0]
        for key in attributes.keys():
            attribute = lasso.Saml2Attribute()
            # Only name/values or name/format/values
            name = None
            values = None
            if type(key) is tuple and len(key) == 2:
                name, format = key
                attribute.nameFormat = format
                values = attributes[(name, format)]
            elif type(key) is tuple and len(key) == 3:
                name, format, nickname = key
                attribute.nameFormat = format
                attribute.friendlyName = nickname
                values = attributes[(name, format, nickname)]
            elif type(key) is tuple:
                return
            else:
                name = key
                attribute.nameFormat = lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC
                values = attributes[key]
            attribute.name = name
            attribute_statement.attribute = \
                list(attribute_statement.attribute) + [attribute]
            attribute_value_list = list(attribute.attributeValue)
            for value in values:
                try:
                    # duck type the ElemenTree interface
                    value.makeelement and value.tag
                    text_node = lasso.MiscTextNode.\
                        newWithXmlNode(ctree.tostring(value))
                except AttributeError:
                    if value is True:
                        value = u'true'
                    elif value is False:
                        value = u'false'
                    else:
                        value = smart_unicode(value)
                    value = value.encode('utf-8')
                    text_node = lasso.MiscTextNode.newWithString(value)
                    text_node.textChild = True
                attribute_value = lasso.Saml2AttributeValue()
                attribute_value.any = [text_node]
                attribute_value_list.append(attribute_value)
            attribute.attributeValue = attribute_value_list
        logger.debug("assertion after processing "
            "%s" % assertion.dump())


def build_assertion(request, login, nid_format='transient', attributes=None):
    """After a successfully validated authentication request, build an
       authentication assertion
    """
    now = datetime.datetime.utcnow()
    logger.info("building assertion at %s" % str(now))
    logger.debug('named Id format is %s' % nid_format)
    # 1 minute ago
    notBefore = now - datetime.timedelta(0, __delta)
    # 1 minute in the future
    notOnOrAfter = now + datetime.timedelta(0, __delta)
    ssl = 'HTTPS' in request.environ
    if __user_backend_from_session:
        backend = request.session[BACKEND_SESSION_KEY]
        logger.debug("authentication from session %s" \
            % backend)
        if backend in ('django.contrib.auth.backends.ModelBackend',
                'authentic2.idp.auth_backends.LogginBackend',
                'django_auth_ldap.backend.LDAPBackend'):
            authn_context = lasso.SAML2_AUTHN_CONTEXT_PASSWORD
        elif backend == 'authentic2.auth2_auth.auth2_ssl.backend.SSLBackend':
            authn_context = lasso.SAML2_AUTHN_CONTEXT_X509
        # XXX: grab context from the assertion received
        elif backend == \
                'authentic2.authsaml2.backends.AuthSAML2PersistentBackend':
            authn_context = lasso.SAML2_AUTHN_CONTEXT_UNSPECIFIED
        elif backend == \
                'authentic2.authsaml2.backends.AuthSAML2TransientBackend':
            authn_context = lasso.SAML2_AUTHN_CONTEXT_UNSPECIFIED
        else:
            backend = load_backend(backend)
            if hasattr(backend, 'get_saml2_authn_context'):
                authn_context = backend.get_saml2_authn_context()
            else:
                raise Exception('backend unsupported: ' + backend)
        if authn_context == lasso.SAML2_AUTHN_CONTEXT_PASSWORD and ssl:
            authn_context = lasso.SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
    else:
        try:
            auth_event = AuthenticationEvent.objects.\
                get(nonce=login.request.id)
            logger.debug("authentication from stored event "
                "%s" % auth_event)
            if auth_event.how == 'password':
                authn_context = lasso.SAML2_AUTHN_CONTEXT_PASSWORD
            elif auth_event.how == 'password-on-https':
                authn_context = \
                    lasso.SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
            elif auth_event.how == 'ssl':
                authn_context = lasso.SAML2_AUTHN_CONTEXT_X509
            elif auth_event.how.startswith('oath-totp'):
                authn_context = lasso.SAML2_AUTHN_CONTEXT_TIME_SYNC_TOKEN
            else:
                raise NotImplementedError('Unknown authentication method %r' \
                    % auth_event.how)
        except ObjectDoesNotExist:
            # TODO: previous session over secure transport (ssl) ?
            authn_context = lasso.SAML2_AUTHN_CONTEXT_PREVIOUS_SESSION
    logger.info("authn_context %s" % authn_context)
    login.buildAssertion(authn_context,
            now.isoformat() + 'Z',
            'unused',  # reauthenticateOnOrAfter is only for ID-FF 1.2
            notBefore.isoformat() + 'Z',
            notOnOrAfter.isoformat() + 'Z')
    assertion = login.assertion
    logger.debug("assertion building in progress %s" \
        % assertion.dump())
    logger.debug("fill assertion")
    fill_assertion(request, login.request, assertion, login.remoteProviderId,
        nid_format)
    # Save federation and new session
    if login.assertion.subject.nameID.format == \
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT:
        logger.debug("nameID persistent, get or create "
            "federation")
        kwargs = nameid2kwargs(login.assertion.subject.nameID)
        service_provider = LibertyServiceProvider.objects \
                .get(liberty_provider__entity_id=login.remoteProviderId)
        federation, new = LibertyFederation.objects.get_or_create(
                sp=service_provider,
                user=request.user, **kwargs)
        if new:
            logger.info("nameID persistent, new federation")
            federation.save()
        else:
            logger.info("nameID persistent, existing "
                "federation")
    else:
        logger.debug("nameID not persistent, no federation "
            "management")
        federation = None
        kwargs = nameid2kwargs(login.assertion.subject.nameID)
    kwargs['entity_id'] = login.remoteProviderId
    kwargs['user'] = request.user
    logger.info("sending nameID %(name_id_format)s: "
        "%(name_id_content)s to %(entity_id)s for user %(user)s" % kwargs)
    if attributes:
        logger.debug("add attributes to the assertion")
        saml2_add_attribute_values(login.assertion, attributes)
    register_new_saml2_session(request, login, federation=federation)


@csrf_exempt
def sso(request):
    """Endpoint for receiving saml2:AuthnRequests by POST, Redirect or SOAP.
       For SOAP a session must be established previously through the login
       page. No authentication through the SOAP request is supported.
    """
    logger.info("performing sso")
    if request.method == "GET":
        logger.debug('called by GET')
        consent_answer = request.GET.get('consent_answer', '')
        if consent_answer:
            logger.info('back from the consent page for federation with \
                answer %s' % consent_answer)
    message = get_saml2_request_message(request)
    server = create_server(request)
    login = lasso.Login(server)
    # 1. Process the request, separate POST and GET treatment
    if not message:
        logger.warn("missing query string")
        return HttpResponseForbidden("A SAMLv2 Single Sign On request need a "
            "query string")
    logger.debug('processing sso request %r' % message)
    policy = None
    signed = True
    while True:
        try:
            login.processAuthnRequestMsg(message)
            break
        except (lasso.ProfileInvalidMsgError,
            lasso.ProfileMissingIssuerError,), e:
            logger.error('invalid message for WebSSO profile with '
                          'HTTP-Redirect binding: %r exception: %s' \
                          % (message, e),
                          extra={'request': request})
            return HttpResponseBadRequest(_("SAMLv2 Single Sign On: "
                "invalid message for WebSSO profile with HTTP-Redirect "
                "binding: %r") % message)
        except lasso.ProfileInvalidProtocolprofileError:
            log_info_authn_request_details(login)
            message = _("SAMLv2 Single Sign On: the request cannot be "
                "answered because no valid protocol binding could be found")
            logger.error("the request cannot be answered because no "
                "valid protocol binding could be found")
            return HttpResponseBadRequest(message)
        except lasso.DsError, e:
            log_info_authn_request_details(login)
            logger.error('digital signature treatment error: %s' % e)
            return return_login_response(request, login)
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError):
            logger.debug('processAuthnRequestMsg not successful')
            log_info_authn_request_details(login)
            provider_id = login.remoteProviderId
            logger.debug('loading provider %s' % provider_id)
            provider_loaded = load_provider(request, provider_id,
                    server=login.server, autoload=True)
            if not provider_loaded:
                message = _('sso: fail to load unknown provider %s' \
                    % provider_id)
                return error_page(request, message, logger=logger,
                        warning=True)
            else:
                policy = get_sp_options_policy(provider_loaded)
                if not policy:
                    logger.error('No policy defined')
                    return error_page(request, _('sso: No SP policy defined'),
                        logger=logger, warning=True)
                logger.info('provider %s loaded with success' \
                    % provider_id)
            if provider_loaded.service_provider.policy.authn_request_signature_check_hint == lasso.PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
                    signed = False
            login.setSignatureVerifyHint(
                    provider_loaded.service_provider.policy \
                            .authn_request_signature_check_hint)
    if signed and not check_destination(request, login.request):
        logger.error('wrong or absent destination')
        return return_login_error(request, login,
                AUTHENTIC_STATUS_CODE_MISSING_DESTINATION)
    # Check NameIDPolicy or force the NameIDPolicy
    name_id_policy = login.request.nameIdPolicy
    logger.debug('nameID policy is %s' % name_id_policy.dump())
    if name_id_policy.format and \
            name_id_policy.format != \
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED:
        nid_format = saml2_urn_to_nidformat(name_id_policy.format)
        logger.debug('nameID format %s' % nid_format)
        default_nid_format = policy.default_name_id_format
        logger.debug('default nameID format %s' % default_nid_format)
        accepted_nid_format = policy.accepted_name_id_format
        logger.debug('nameID format accepted %s' \
            % str(accepted_nid_format))
        if (not nid_format or nid_format not in accepted_nid_format) and \
           default_nid_format != nid_format:
            set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_INVALID_NAME_ID_POLICY)
            logger.error('NameID format required is not accepted')
            return finish_sso(request, login)
    else:
        logger.debug('no nameID policy format')
        nid_format = policy.default_name_id_format or 'transient'
        logger.debug('set nameID policy format %s' % nid_format)
        name_id_policy.format = nidformat_to_saml2_urn(nid_format)
    return sso_after_process_request(request, login, nid_format=nid_format)


def need_login(request, login, save, nid_format):
    """Redirect to the login page with a nonce parameter to verify later that
       the login form was submitted
    """
    nonce = login.request.id or get_nonce()
    save_key_values(nonce, login.dump(), False, save, nid_format)
    url = reverse(continue_sso) + '?%s=%s' % (NONCE_FIELD_NAME, nonce)
    logger.debug('redirect to login page with next url %s' % url)
    return redirect_to_login(url,
            other_keys={NONCE_FIELD_NAME: nonce})


def get_url_with_nonce(request, function, nonce):
    url = reverse(function) + '?%s=%s' % (NONCE_FIELD_NAME, nonce)
    return urllib.quote(url)


def need_consent_for_federation(request, login, save, nid_format):
    nonce = login.request.id or get_nonce()
    save_key_values(nonce, login.dump(), False, save, nid_format)
    display_name = None
    try:
        provider = \
            LibertyProvider.objects.get(entity_id=login.request.issuer.content)
        display_name = provider.name
    except ObjectDoesNotExist:
        pass
    if not display_name:
        display_name = urllib.quote(login.request.issuer.content)
    url = '%s?%s=%s&next=%s&provider_id=%s' \
        % (reverse(consent_federation), NONCE_FIELD_NAME,
            nonce, get_url_with_nonce(request, continue_sso, nonce),
            display_name)
    logger.debug('redirect to url %s' % url)
    return HttpResponseRedirect(url)


def need_consent_for_attributes(request, login, consent_obtained, save,
        nid_format):
    nonce = login.request.id or get_nonce()
    save_key_values(nonce, login.dump(), consent_obtained, save, nid_format)
    display_name = None
    try:
        provider = \
            LibertyProvider.objects.get(entity_id=login.request.issuer.content)
        display_name = provider.name
    except ObjectDoesNotExist:
        pass
    if not display_name:
        display_name = urllib.quote(login.request.issuer.content)
    url = '%s?%s=%s&next=%s&provider_id=%s' \
        % (reverse(consent_attributes), NONCE_FIELD_NAME,
            nonce, get_url_with_nonce(request, continue_sso, nonce),
            display_name)
    logger.debug('redirect to url %s' % url)
    return HttpResponseRedirect(url)


def continue_sso(request):
    consent_answer = None
    consent_attribute_answer = None
    if request.method == "GET":
        logger.debug('called by GET')
        consent_answer = request.GET.get('consent_answer', '')
        if consent_answer:
            logger.info("back from the consent page for "
                "federation with answer %s" \
                    % consent_answer)
        consent_attribute_answer = \
            request.GET.get('consent_attribute_answer', '')
        if consent_attribute_answer:
            logger.info("back from the consent page for "
                "attributes %s" % consent_attribute_answer)
    nonce = request.REQUEST.get(NONCE_FIELD_NAME, '')
    if not nonce:
        logger.warning('nonce not found')
        return HttpResponseBadRequest()
    login_dump, consent_obtained, save, nid_format = \
            get_and_delete_key_values(nonce)
    server = create_server(request)
    # Work Around for lasso < 2.3.6
    login_dump = login_dump.replace('<Login ', '<lasso:Login ') \
            .replace('</Login>', '</lasso:Login>')
    login = lasso.Login.newFromDump(server, login_dump)
    logger.debug('login newFromDump done')
    if not login:
        return error_page(request, _('continue_sso: error loading login'),
            logger=logger)
    if not load_provider(request, login.remoteProviderId, server=login.server,
            autoload=True):
        return error_page(request, _('continue_sso: unknown provider %s') \
            % login.remoteProviderId, logger=logger)
    if 'cancel' in request.GET:
        logger.info('login canceled')
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login)
    if consent_answer == 'refused':
        logger.info("consent answer treatment, the user "
            "refused, return request denied to the requester")
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login)
    if consent_answer == 'accepted':
        logger.info("consent answer treatment, the user "
            "accepted, continue")
        consent_obtained = True
    return sso_after_process_request(request, login,
            consent_obtained=consent_obtained,
            consent_attribute_answer=consent_attribute_answer,
            nid_format=nid_format)


def sso_after_process_request(request, login, consent_obtained=False,
        consent_attribute_answer=False, user=None, save=True,
        nid_format='transient', return_profile=False):
    """Common path for sso and idp_initiated_sso.

       consent_obtained: whether the user has given his consent to this
       federation
       user: the user which must be federated, if None, current user is the
       default.
       save: whether to save the result of this transaction or not.
    """
    nonce = login.request.id
    user = user or request.user
    did_auth = AuthenticationEvent.objects.filter(nonce=nonce).exists()
    force_authn = login.request.forceAuthn
    passive = login.request.isPassive

    logger.debug('named Id format is %s' \
        % nid_format)

    if not passive and \
            (user.is_anonymous() or (force_authn and not did_auth)):
        logger.info('login required')
        return need_login(request, login, save, nid_format)

    #Deal with transient users
    transient_user = False
    # XXX: Deal with all kind of transient users
    type(SAML2TransientUser)
    if isinstance(request.user, SAML2TransientUser):
        logger.debug('the user is transient')
        transient_user = True
    if transient_user and login.request.nameIdPolicy.format == \
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT:
        logger.info("access denied, the user is "
            "transient and the sp ask for persistent")
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login)
    # If the sp does not allow create, reject
    if transient_user and login.request.nameIdPolicy.allowCreate == 'false':
        logger.info("access denied, we created a "
            "transient user and allow creation is not authorized by the SP")
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login)

    #Do not ask consent for federation if a transient nameID is provided
    transient = False
    if login.request.nameIdPolicy.format == \
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT:
        transient = True

    decisions = idp_signals.authorize_service.send(sender=None,
         request=request, user=request.user, audience=login.remoteProviderId)
    logger.info('signal authorize_service sent')

    # You don't dream. By default, access granted.
    # We catch denied decisions i.e. dic['authz'] = False
    access_granted = True
    for decision in decisions:
        logger.info('authorize_service connected '
            'to function %s' % decision[0].__name__)
        dic = decision[1]
        if dic and 'authz' in dic:
            logger.info('decision is %s' \
                % dic['authz'])
            if 'message' in dic:
                logger.info('with message %s' \
                    % dic['message'])
            if not dic['authz']:
                logger.info('access denied by '
                    'an external function')
                access_granted = False
        else:
            logger.info('no function connected to '
                'authorize_service')

    if not access_granted:
        logger.info('access denied, return answer '
            'to the requester')
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login)

    provider = load_provider(request, login.remoteProviderId,
        server=login.server)
    if not provider:
        logger.info(''
            'sso for an unknown provider %s' % login.remoteProviderId)
        return error_page(request,
            _('Provider %s is unknown') % login.remoteProviderId,
            logger=logger)
    policy = get_sp_options_policy(provider)
    if not policy:
        logger.error('No policy defined for '
            'provider %s' % login.remoteProviderId)
        return error_page(request, _('No service provider policy defined'),
            logger=logger)

    '''User consent for federation management

       1- Check if the policy enforce the consent
       2- Check if there is an existing federation (consent already given)
       3- If no, send a signal to bypass consent
       4- If no bypass captured, ask for the user consent
       5- Yes, continue, No, return error to the service provider

    From the core SAML2 specs.

        'urn:oasis:names:tc:SAML:2.0:consent:unspecified'
    No claim as to principal consent is being made.

        'urn:oasis:names:tc:SAML:2.0:consent:obtained'
    Indicates that a principal's consent has been obtained by the issuer of
    the message.

        'urn:oasis:names:tc:SAML:2.0:consent:prior'
    Indicates that a principal's consent has been obtained by the issuer of
    the message at some point prior to the action that initiated the message.

        'urn:oasis:names:tc:SAML:2.0:consent:current-implicit'
    Indicates that a principal's consent has been implicitly obtained by the
    issuer of the message during the action that initiated the message, as
    part of a broader indication of consent. Implicit consent is typically
    more proximal to the action in time and presentation than prior consent,
    such as part of a session of activities.

        'urn:oasis:names:tc:SAML:2.0:consent:current-explicit'
    Indicates that a principal's consent has been explicitly obtained by the
    issuer of the message during the action that initiated the message.

        'urn:oasis:names:tc:SAML:2.0:consent:unavailable'
    Indicates that the issuer of the message did not obtain consent.

        'urn:oasis:names:tc:SAML:2.0:consent:inapplicable'
    Indicates that the issuer of the message does not believe that they need
    to obtain or report consent
    '''

    logger.debug('the user consent status before process is %s' \
        % str(consent_obtained))

    consent_value = None
    if consent_obtained:
        consent_value = 'urn:oasis:names:tc:SAML:2.0:consent:current-explicit'
    else:
        consent_value = 'urn:oasis:names:tc:SAML:2.0:consent:unavailable'

    if not consent_obtained and not transient:
        consent_obtained = \
                not policy.ask_user_consent
        logger.debug('the policy says %s' \
            % str(consent_obtained))
        if consent_obtained:
            #The user consent is bypassed by the policy
            consent_value = 'urn:oasis:names:tc:SAML:2.0:consent:unspecified'

    try:
        LibertyFederation.objects.get(
                user=request.user,
                sp__liberty_provider__entity_id=login.remoteProviderId)
        logger.debug('consent already '
            'given (existing federation) for %s' % login.remoteProviderId)
        consent_obtained = True
        '''This is abusive since a federation may exist even if we have
        not previously asked the user consent.'''
        consent_value = 'urn:oasis:names:tc:SAML:2.0:consent:prior'
    except ObjectDoesNotExist:
        logger.debug('consent not yet given \
            (no existing federation) for %s' % login.remoteProviderId)

    if not consent_obtained and not transient:
        logger.debug('signal avoid_consent sent')
        avoid_consent = idp_signals.avoid_consent.send(sender=None,
             request=request, user=request.user,
             audience=login.remoteProviderId)
        for c in avoid_consent:
            logger.info('avoid_consent connected '
                'to function %s' % c[0].__name__)
            if c[1] and 'avoid_consent' in c[1] and c[1]['avoid_consent']:
                logger.debug('\
                    avoid consent by signal')
                consent_obtained = True
                #The user consent is bypassed by the signal
                consent_value = \
                    'urn:oasis:names:tc:SAML:2.0:consent:unspecified'

    if not consent_obtained and not transient:
        logger.debug('ask the user consent now')
        return need_consent_for_federation(request, login, save, nid_format)

    policy = get_attribute_policy(provider)

    attributes_provided = \
        idp_signals.add_attributes_to_response.send(sender=None,
            request=request, user=request.user,
            audience=login.remoteProviderId)
    logger.info(''
        'signal add_attributes_to_response sent')

    attributes = {}
    for attrs in attributes_provided:
        logger.info('add_attributes_to_response '
            'connected to function %s' % attrs[0].__name__)
        if attrs[1] and 'attributes' in attrs[1]:
            dic = attrs[1]
            logger.info('attributes provided are '
                '%s' % str(dic['attributes']))
            for key in dic['attributes'].keys():
                attributes[key] = dic['attributes'][key]

    if not policy and attributes:
        logger.info('no attribute policy, we do '
            'not forward attributes')
        attributes = None
    elif policy and policy.ask_consent_attributes and attributes:
        if not consent_attribute_answer:
            logger.info('consent for attribute '
                'propagation')
            request.session['attributes_to_send'] = attributes
            request.session['allow_attributes_selection'] = \
                policy.allow_attributes_selection
            return need_consent_for_attributes(request, login,
                consent_obtained, save, nid_format)
        if consent_attribute_answer == 'accepted' and \
                policy.allow_attributes_selection:
            attributes = request.session['attributes_to_send']
        elif consent_attribute_answer == 'refused':
            attributes = None

    logger.debug(''
        'login dump before processing %s' % login.dump())
    try:
        if not transient:
            logger.debug('load identity dump')
            load_federation(request, get_entity_id(request, reverse(metadata)), login, user)
        load_session(request, login)
        logger.debug('load session')
        login.validateRequestMsg(not user.is_anonymous(), consent_obtained)
        logger.debug('validateRequestMsg %s' \
            % login.dump())
    except lasso.LoginRequestDeniedError:
        logger.error('access denied due to LoginRequestDeniedError')
        set_saml2_response_responder_status_code(login.response,
            lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login, user=user, save=save)
    except lasso.LoginFederationNotFoundError:
        logger.error('access denied due to LoginFederationNotFoundError')
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login, user=user, save=save)

    login.response.consent = consent_value

    build_assertion(request, login, nid_format=nid_format,
            attributes=attributes)
    return finish_sso(request, login, user=user, save=save, return_profile=return_profile)


def return_login_error(request, login, error):
    """Set the first level status code to Responder, the second level to error
    and return the response message for the assertionConsumer"""
    logger.debug('error %s' % error)
    set_saml2_response_responder_status_code(login.response, error)
    return return_login_response(request, login)


def return_login_response(request, login):
    '''Return the AuthnResponse message to the assertion consumer'''
    if login.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_ART:
        login.buildArtifactMsg(lasso.HTTP_METHOD_ARTIFACT_GET)
        logger.info('sending Artifact to assertionConsumer %r' % login.msgUrl)
        save_artifact(request, login)
    elif login.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_POST:
        login.buildAuthnResponseMsg()
        logger.info('sending POST to assertionConsumer %r' % login.msgUrl)
        logger.debug('POST content %r' % login.msgBody)
    else:
        logger.error('NotImplementedError with login %s' % login.dump())
        raise NotImplementedError()
    provider = LibertyProvider.objects.get(entity_id=login.remoteProviderId)
    return return_saml2_response(request, login,
        title=_('You are being redirected to "%s"') % provider.name)


def finish_sso(request, login, user=None, save=False, return_profile=False):
    logger.info('finishing sso...')
    if user is None:
        logger.debug('user is None')
        user = request.user
    response = return_login_response(request, login)
    if save:
        save_session(request, login)
        logger.debug('session saved')
    logger.info('sso treatment ended, send response')
    if return_profile:
        return login
    return response


def save_artifact(request, login):
    '''Remember an artifact message for later retrieving'''
    LibertyArtifact(artifact=login.artifact,
            content=login.artifactMessage.decode('utf-8'),
            provider_id=login.remoteProviderId).save()
    logger.debug('artifact saved')


def reload_artifact(login):
    try:
        art = LibertyArtifact.objects.get(artifact=login.artifact)
        logger.debug('artifact found')
        login.artifactMessage = art.content.encode('utf-8')
        logger.debug('artifact loaded')
        art.delete()
        logger.debug('artifact deleted')
    except ObjectDoesNotExist:
        logger.debug('no artifact found')
        pass


@csrf_exempt
def artifact(request):
    '''Resolve a SAMLv2 ArtifactResolve request
    '''
    logger.info('soap call received')
    soap_message = get_soap_message(request)
    logger.debug('soap message %r' % soap_message)
    server = create_server(request)
    login = lasso.Login(server)
    try:
        login.processRequestMsg(soap_message)
    except (lasso.ProfileUnknownProviderError, lasso.ParamError):
        if not load_provider(request, login.remoteProviderId,
                server=login.server):
            logger.error('provider loading failure')
        try:
            login.processRequestMsg(soap_message)
        except lasso.DsError, e:
            logger.error('signature error for %s: %s'
                    % (e, login.remoteProviderId))
        else:
            logger.info('reloading artifact')
            reload_artifact(login)
    except:
        logger.exception('resolve error')
    try:
        login.buildResponseMsg(None)
        logger.debug('resolve response %s' % login.msgBody)
    except:
        logger.exception('resolve error')
        return soap_fault(faultcode='soap:Server',
                faultstring='Internal Server Error')
    logger.info('treatment ended, return answer')
    return return_saml_soap_response(login)


def check_delegated_authentication_permission(request):
    logger.info('superuser? %s' \
        % str(request.user.is_superuser()))
    return request.user.is_superuser()


@csrf_exempt
@login_required
def idp_sso(request, provider_id=None, user_id=None, nid_format=None,
        save=True, return_profile=False):
    '''Initiate an SSO toward provider_id without a prior AuthnRequest
    '''
    User = get_user_model()
    if request.method == 'GET':
        logger.info('to initiate a sso we need a post form')
        return error_page(request,
            _('Error trying to initiate a single sign on'), logger=logger)
    if not provider_id:
        provider_id = request.POST.get('provider_id')
    if not provider_id:
        logger.info('to initiate a sso we need a provider_id')
        return error_page(request,
            _('A provider identifier was not provided'), logger=logger)
    logger.info('sso initiated with %(provider_id)s' \
        % {'provider_id': provider_id})
    if user_id:
        logger.info('sso as %s' % user_id)
    server = create_server(request)
    login = lasso.Login(server)
    liberty_provider = load_provider(request, provider_id,
        server=login.server)
    if not liberty_provider:
        logger.info('sso for an unknown provider %s' % provider_id)
        return error_page(request, _('Provider %s is unknown') % provider_id,
            logger=logger)
    if user_id:
        user = User.get(id=user_id)
        if not check_delegated_authentication_permission(request):
            logger.warning('%r tried to log as %r on %r but was '
                'forbidden' % (request.user, user, provider_id))
            return HttpResponseForbidden('You must be superuser to log as '
                'another user')
    else:
        user = request.user
        logger.info('sso by %r' % user)
    load_federation(request, get_entity_id(request, reverse(metadata)), login, user)
    logger.debug('federation loaded')
    login.initIdpInitiatedAuthnRequest(provider_id)
    # Control assertion consumer binding
    policy = get_sp_options_policy(liberty_provider)
    if not policy:
        logger.error('No policy defined, \
            unable to set protocol binding')
        return error_page(request, _('idp_sso: No SP policy defined'),
            logger=logger)
    binding = policy.prefered_assertion_consumer_binding
    logger.debug('binding is %r' % binding)
    if binding == 'meta':
        pass
    elif binding == 'art':
        login.request.protocolBinding = lasso.SAML2_METADATA_BINDING_ARTIFACT
    elif binding == 'post':
        login.request.protocolBinding = lasso.SAML2_METADATA_BINDING_POST
    else:
        logger.error('unsupported protocol binding %r' % binding)
        return error_page(request, _('Server error'), logger=logger)
    # Control nid format policy
    # XXX: if a federation exist, we should use transient
    if nid_format:
        logger.debug('nameId format is %r' % nid_format)
        if not nid_format in policy.accepted_name_id_format:
            logger.error('name id format %r is not supported by %r' \
                % (nid_format, provider_id))
            raise Http404('Provider %r does not support this name id format' \
                % provider_id)
    if not nid_format:
        nid_format = policy.default_name_id_format
        logger.debug('nameId format is %r' % nid_format)
    login.request.nameIdPolicy.format = nidformat_to_saml2_urn(nid_format)
    login.request.nameIdPolicy.allowCreate = True

    login.processAuthnRequestMsg(None)

    return sso_after_process_request(request, login,
            consent_obtained=False, user=user, save=save,
            nid_format=nid_format, return_profile=return_profile)


def finish_slo(request):
    id = request.REQUEST.get('id')
    if not id:
        logger.error('missing id argument')
        return HttpResponseBadRequest('finish_slo: missing id argument')
    logout_dump, session_key = get_and_delete_key_values(id)
    server = create_server(request)
    logout = lasso.Logout.newFromDump(server, logout_dump)
    load_provider(request, logout.remoteProviderId, server=logout.server)
    # Clean all session
    all_sessions = \
        LibertySession.objects.filter(django_session_key=session_key)
    if all_sessions.exists():
        all_sessions.delete()
        return return_logout_error(request, logout,
            lasso.SAML2_STATUS_CODE_PARTIAL_LOGOUT)
    try:
        logout.buildResponseMsg()
    except:
        logger.exception('failure to build reponse msg')
        pass
    provider = LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
    return return_saml2_response(request, logout,
        title=_('You are being redirected to "%s"') % provider.name)


def return_logout_error(request, logout, error):
    logout.buildResponseMsg()
    set_saml2_response_responder_status_code(logout.response, error)
    # Hack because response is not initialized before
    # buildResponseMsg
    logout.buildResponseMsg()
    logger.debug('send an error message %s' % error)
    provider = LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
    return return_saml2_response(request, logout,
        title=_('You are being redirected to "%s"') % provider.name)


def process_logout_request(request, message, binding):
    '''Do the first part of processing a logout request'''
    server = create_server(request)
    logout = lasso.Logout(server)
    if not message:
        return logout, HttpResponseBadRequest('No message was present')
    logger.debug('slo with binding %s message %s' \
        % (binding, message))
    try:
        try:
            logout.processRequestMsg(message)
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError):
            logger.debug('loading provider %s' \
                % logout.remoteProviderId)
            p = load_provider(request, logout.remoteProviderId,
                    server=logout.server)
            if not p:
                logger.error(''
                    'slo unknown provider %s' % logout.remoteProviderId)
                return logout, return_logout_error(request, logout,
                        AUTHENTIC_STATUS_CODE_UNKNOWN_PROVIDER)
            # we do not verify authn request, why verify logout requests...
            logout.setSignatureVerifyHint(
                    p.service_provider.policy \
                            .authn_request_signature_check_hint)
            logout.processRequestMsg(message)
    except lasso.DsError:
        logger.error(''
            'slo signature error on request %s' % message)
        return logout, return_logout_error(request, logout,
                lasso.LIB_STATUS_CODE_INVALID_SIGNATURE)
    except Exception:
        logger.exception(''
            'slo unknown error when processing a request %s' % message)
        return logout, HttpResponseBadRequest('Invalid logout request')
    if binding != 'SOAP' and not check_destination(request, logout.request):
        logger.error(''
            'slo wrong or absent destination')
        return logout, return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_MISSING_DESTINATION)
    return logout, None


def log_logout_request(logout):
    name_id = nameid2kwargs(logout.request.nameId)
    session_indexes = logout.request.sessionIndexes
    logger.info('slo nameid: %s session_indexes: %s' \
        % (name_id, session_indexes))


def validate_logout_request(request, logout, idp=True):
    if not isinstance(logout.request.nameId, lasso.Saml2NameID):
        logger.error('slo request lacks a NameID')
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_MISSING_NAMEID)
    # only idp have the right to send logout request without session indexes
    if not logout.request.sessionIndexes and idp:
        logger.error(''
            'slo request lacks SessionIndex')
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_MISSING_SESSION_INDEX)
    logger.info('valid logout request')
    log_logout_request(logout)
    return None


def logout_synchronous_other_backends(request, logout, django_sessions_keys):
    backends = idp.get_backends()
    if backends:
        logger.info('backends %s' \
            % str(backends))
    else:
        logger.info('no backends')
    ok = True
    for backend in backends:
        ok = ok and backends.can_synchronous_logout(django_sessions_keys)
    if not ok:
        return return_logout_error(request, logout,
                lasso.SAML2_STATUS_CODE_UNSUPPORTED_BINDING)
    logger.info('treatments ended')
    return None


def get_only_last_session(name_id, session_indexes, but_provider):
    """Try to have a decent behaviour when receiving a logout request with
       multiple session indexes.

       Enumerate all emitted assertions for the given session, and for each
       provider only keep the more recent one.
    """
    logger.debug('%s %s' % (name_id.dump(),
        session_indexes))
    lib_session1 = LibertySession.get_for_nameid_and_session_indexes(
            name_id, session_indexes)
    django_session_keys = [s.django_session_key for s in lib_session1]
    lib_session = LibertySession.objects.filter(
            django_session_key__in=django_session_keys)
    providers = set([s.provider_id for s in lib_session])
    result = []
    for provider in providers:
        if provider != but_provider:
            x = lib_session.filter(provider_id=provider)
            latest = x.latest('creation')
            result.append(latest)
    if lib_session1:
        logger.debug('last session %s' % lib_session1)
    return lib_session1, result, django_session_keys


def build_session_dump(elements):
    '''Build a session dump from a list of pairs
       (provider_id,assertion_content)'''
    session = [u'<Session xmlns="http://www.entrouvert.org/namespaces/lasso/0.0" Version="2">']
    for x in elements:
        session.append(u'<Assertion RemoteProviderID="%s">%s</Assertion>' % x)
    session.append(u'</Session>')
    s = ''.join(session)
    logger.debug('session built %s' % s)
    return s


def set_session_dump_from_liberty_sessions(profile, lib_sessions):
    '''Extract all assertion from a list of lib_sessions, and create a session
    dump from them'''
    logger.debug('lib_sessions %s' \
        % lib_sessions)
    l = [(lib_session.provider_id, lib_session.assertion.assertion) \
            for lib_session in lib_sessions]
    profile.setSessionFromDump(build_session_dump(l).encode('utf8'))
    logger.debug('profile %s' \
        % profile.session.dump())


@csrf_exempt
def slo_soap(request):
    """Endpoint for receiveing saml2:AuthnRequest by SOAP"""
    message = get_soap_message(request)
    if not message:
        logger.error('no message received')
        return HttpResponseBadRequest('Bad SOAP message')
    logger.info('soap message received %s' % message)
    logout, error = process_logout_request(request, message, 'SOAP')
    if error:
        return error
    error = validate_logout_request(request, logout, idp=True)
    if error:
        return error

    try:
        provider = \
            LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
    except ObjectDoesNotExist:
        logger.warn('provider %r unknown' \
            % logout.remoteProviderId)
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_UNAUTHORIZED)
    policy = get_sp_options_policy(provider)
    if not policy:
        logger.error('No policy found for %s'\
             % logout.remoteProviderId)
        return return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_UNAUTHORIZED)
    if not policy.accept_slo:
        logger.warn('received slo from %s not authorized'\
             % logout.remoteProviderId)
        return return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_UNAUTHORIZED)

    '''Find all active sessions on SPs but the SP initiating the SLO'''
    found, lib_sessions, django_session_keys = \
            get_only_last_session(logout.request.nameId,
                    logout.request.sessionIndexes, logout.remoteProviderId)
    if not found:
        logger.debug('no third SP session found')
    else:
        logger.info('begin SP sessions processing...')
        for lib_session in lib_sessions:
            p = load_provider(request, lib_session.provider_id,
                    server=logout.server)
            if not p:
                logger.error('slo cannot logout provider %s, it is '
                    'no more known.' % lib_session.provider_id)
                continue
            else:
                logger.info('provider %s loaded' % str(p))
                policy = get_sp_options_policy(p)
                if not policy:
                    logger.error('No policy found for %s' \
                        % lib_session.provider_id)
                elif not policy.forward_slo:
                    logger.info('%s configured to not reveive slo' \
                        % lib_session.provider_id)
                if not policy or not policy.forward_slo:
                    lib_sessions.remove(lib_session)
        set_session_dump_from_liberty_sessions(logout,
            found[0:1] + lib_sessions)
        try:
            logout.validateRequest()
        except lasso.LogoutUnsupportedProfileError:
            '''
                If one provider does not support SLO by SOAP,
                continue with others!
            '''
            logger.error('one provider does \
                not support SOAP %s' % [s.provider_id for s in lib_sessions])
        except Exception, e:
            logger.exception('slo, unknown error %s' % str(e))
            logout.buildResponseMsg()
            provider = LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
            return return_saml2_response(request, logout,
                title=_('You are being redirected to "%s"') % provider.name)
        for lib_session in lib_sessions:
            try:
                logger.info('slo, relaying logout to provider %s' \
                    % lib_session.provider_id)
                '''
                    As we are in a synchronous binding, we need SOAP support
                '''
                logout.initRequest(lib_session.provider_id,
                    lasso.HTTP_METHOD_SOAP)
                logout.buildRequestMsg()
                if logout.msgBody:
                    logger.info('slo by SOAP')
                    soap_response = send_soap_request(request, logout)
                    logout.processResponseMsg(soap_response)
                else:
                    logger.info('Provider does not support SOAP')
            except lasso.Error:
                logger.exception('slo, relaying to %s failed ' %
                        lib_session.provider_id)

    #Send SLO to IdP
    pid = None
    q = LibertySessionDump. \
            objects.filter(django_session_key__in=django_session_keys,
                    kind=LIBERTY_SESSION_DUMP_KIND_SP)
    if not q:
        logger.info('No session found for a third IdP')
    else:
        from authentic2.authsaml2 import saml2_endpoints
        server = saml2_endpoints.create_server(request)
        logout2 = lasso.Logout(server)
        for s in q:
            try:
                lib_session = lasso.Session().newFromDump(s.session_dump)
            except lasso.Error:
                logger.debug('Unable to load session %s' % s)
            else:
                try:
                    pid = lib_session.get_assertions().keys()[0]
                    logger.debug('SLO to %s' % pid)
                    logout2.setSessionFromDump(s.session_dump.encode('utf8'))
                    provider = load_provider(request, pid,
                        server=server, sp_or_idp='idp')
                    policy = get_idp_options_policy(provider)
                    if not policy:
                        logger.error('No policy found for %s'\
                             % provider)
                    elif not policy.forward_slo:
                        logger.info('%s configured to not reveive \
                            slo' % provider)
                    else:
                        '''
                            As we are in a synchronous binding,
                            we need SOAP support
                        '''
                        logout2.initRequest(None, lasso.HTTP_METHOD_SOAP)
                        logout2.buildRequestMsg()
                        soap_response = send_soap_request(request, logout2)
                        logout2.processRequestMsg(soap_response)
                        logger.info('successful SLO with %s' \
                            % pid)
                except Exception, e:
                    logger.error('error treating SLO with IdP %s' \
                        % str(e))

    '''
        Respond to the SP initiating SLO
    '''
    try:
        logout.buildResponseMsg()
    except lasso.Error:
        logger.exception('slo failure to build reponse msg')
        raise NotImplementedError()
    logger.info('processing finished')
    logger.exception('kill django sessions')
    kill_django_sessions(django_session_keys)
    provider = LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
    return return_saml2_response(request, logout,
        title=_('You are being redirected to "%s"') % provider.name)


@csrf_exempt
def slo(request):
    """Endpoint for receiving SLO by POST, Redirect.
    """
    message = get_saml2_request_message_async_binding(request)
    logout, response = process_logout_request(request, message,
        request.method)
    if response:
        return response
    logger.debug('asynchronous slo message %s' % message)

    try:
        provider = \
            LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
    except ObjectDoesNotExist:
        logger.warn('provider %r unknown' \
            % logout.remoteProviderId)
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_UNAUTHORIZED)
    policy = get_sp_options_policy(provider)
    if not policy:
        logger.error('No policy found for %s'\
             % logout.remoteProviderId)
        return return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_UNAUTHORIZED)
    if not policy.accept_slo:
        logger.warn('received slo from %s not authorized'\
             % logout.remoteProviderId)
        return return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_UNAUTHORIZED)

    try:
        try:
            logout.processRequestMsg(message)
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError), e:
            load_provider(request, logout.remoteProviderId,
                    server=logout.server)
            logout.processRequestMsg(message)
    except lasso.DsError, e:
        logger.exception('signature error %s' % e)
        logout.buildResponseMsg()
        provider = LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
        return return_saml2_response(request, logout,
            title=_('You are being redirected to "%s"') % provider.name)
    except Exception, e:
        logger.exception('slo %s' % message)
        return error_page(_('Invalid logout request'), logger=logger)
    session_indexes = logout.request.sessionIndexes
    if len(session_indexes) == 0:
        logger.error('slo received a request from %s without any \
            SessionIndex, it is forbidden' % logout.remoteProviderId)
        logout.buildResponseMsg()
        provider = LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
        return return_saml2_response(request, logout,
            title=_('You are being redirected to "%s"') % provider.name)
    logger.info('asynchronous slo from %s' % logout.remoteProviderId)
    # Filter sessions
    all_sessions = LibertySession.get_for_nameid_and_session_indexes(
            logout.request.nameId, logout.request.sessionIndexes)
    # Does the request is valid ?
    remote_provider_sessions = \
            all_sessions.filter(provider_id=logout.remoteProviderId)
    if not remote_provider_sessions.exists():
        logger.error('slo refused, since no session exists with the \
            requesting provider')
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_UNKNOWN_SESSION)
    # Load session dump for the requesting provider
    last_session = remote_provider_sessions.latest('creation')
    set_session_dump_from_liberty_sessions(logout, [last_session])
    try:
        logout.validateRequest()
    except:
        logger.exception('slo error')
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_INTERNAL_SERVER_ERROR)
    # Now clean sessions for this provider
    LibertySession.objects.filter(provider_id=logout.remoteProviderId,
            django_session_key=request.session.session_key).delete()
    # Save some values for cleaning up
    save_key_values(logout.request.id, logout.dump(),
            request.session.session_key)
    return idp_views.redirect_to_logout(request, next_page='%s?id=%s' %
            (reverse(finish_slo), urllib.quote(logout.request.id)))


def ko_icon(request):
    return HttpResponseRedirect('%s/authentic2/images/ko.png' \
        % settings.STATIC_URL)


def ok_icon(request):
    return HttpResponseRedirect('%s/authentic2/images/ok.png' \
        % settings.STATIC_URL)


@csrf_exempt
@login_required
def idp_slo(request, provider_id=None):
    """Send a single logout request to a SP, if given a next parameter, return
    to this URL, otherwise redirect to an icon symbolizing failure or success
    of the request

    provider_id - entity id of the service provider to log out
    all - if present, logout all sessions by omitting the SessionIndex element
    """
    all = request.REQUEST.get('all')
    next = request.REQUEST.get('next')

    logger.debug('provider_id in parameter %s' % str(provider_id))

    if request.method == 'GET' and 'provider_id' in request.GET:
        provider_id = request.GET.get('provider_id')
        logger.debug('provider_id from GET %s' % str(provider_id))
    if request.method == 'POST' and 'provider_id' in request.POST:
        provider_id = request.POST.get('provider_id')
        logger.debug('provider_id from POST %s' % str(provider_id))
    if not provider_id:
        logger.info('to initiate a slo we need a provider_id')
        return HttpResponseRedirect(next) or ko_icon(request)
    logger.info('slo initiated with %(provider_id)s' \
        % {'provider_id': provider_id})

    server = create_server(request)
    logout = lasso.Logout(server)

    provider = load_provider(request, provider_id, server=logout.server)
    if not provider:
        logger.error('slo failed to load provider')
    policy = get_sp_options_policy(provider)
    if not policy:
        logger.error('No policy found for %s'\
             % provider_id)
        return HttpResponseRedirect(next) or ko_icon(request)
    if not policy.forward_slo:
        logger.warn('slo asked for %s configured to not reveive '
            'slo' % provider_id)
        return HttpResponseRedirect(next) or ko_icon(request)

    lib_sessions = LibertySession.objects.filter(
        django_session_key=request.session.session_key,
        provider_id=provider_id)
    if lib_sessions:
        logger.debug('%d lib_sessions found', lib_sessions.count())
        set_session_dump_from_liberty_sessions(logout, [lib_sessions[0]])
    try:
        logout.initRequest(provider_id)
    except (lasso.ProfileMissingAssertionError,
            lasso.ProfileSessionNotFoundError):
        logger.error('slo failed because no sessions exists for %r' \
            % provider_id)
        return redirect_next(request, next) or ko_icon(request)
    if all is not None:
        logout.request.sessionIndexes = []
    else:
        session_indexes = lib_sessions.values_list('session_index', flat=True)
        logout.request.sessionIndexes = tuple(map(lambda x: x.encode('utf8'),
            session_indexes))
    logout.msgRelayState = logout.request.id
    try:
        logout.buildRequestMsg()
    except:
        logger.exception('slo misc error')
        return redirect_next(request, next) or ko_icon(request)
    if logout.msgBody:
        logger.info('slo by SOAP')
        try:
            soap_response = send_soap_request(request, logout)
        except Exception, e:
            logger.exception('slo SOAP failure due to %s' % str(e))
            return redirect_next(request, next) or ko_icon(request)
        return process_logout_response(request, logout, soap_response, next)
    else:
        logger.info('slo by redirect')
        save_key_values(logout.request.id, logout.dump(), provider_id, next)
        return HttpResponseRedirect(logout.msgUrl)


def process_logout_response(request, logout, soap_response, next):
    logger.info('soap_response is %s' % str(soap_response))
    try:
        logout.processResponseMsg(soap_response)
    except getattr(lasso, 'ProfileRequestDeniedError', lasso.LogoutRequestDeniedError):
        logger.warning('logout request was denied')
        return redirect_next(request, next) or ko_icon(request)
    except:
        logger.exception('\
            slo error with soap response %r and logout dump %r' \
                % (soap_response, logout.dump()))
    else:
        LibertySession.objects.filter(
                    django_session_key=request.session.session_key,
                    provider_id=logout.remoteProviderId).delete()
        logger.info('deleted session to %s',
                logout.remoteProviderId)
    return redirect_next(request, next) or ok_icon(request)


def slo_return(request):
    next = None
    logger.info('return from redirect')
    relay_state = request.REQUEST.get('RelayState')
    if not relay_state:
        logger.error('slo no relay state in response')
        return error_page('Missing relay state', logger=logger)
    else:
        logger.debug('relay_state %s' % relay_state)
    try:
        logout_dump, provider_id, next = \
            get_and_delete_key_values(relay_state)
    except:
        logger.exception('slo bad relay state in response')
        return error_page('Bad relay state', logger=logger)
    server = create_server(request)
    logout = lasso.Logout.newFromDump(server, logout_dump)
    provider_id = logout.remoteProviderId
    # forced to reset signature_verify_hint as it is not saved in the dump
    provider = load_provider(request, provider_id, server=server)
    policy = provider.service_provider.get_policy()
    # FIXME: should use a logout_request_signature_check_hint
    logout.setSignatureVerifyHint(policy.authn_request_signature_check_hint)
    if not load_provider(request, provider_id, server=logout.server):
        logger.error('slo failed to load provider')
    return process_logout_response(request, logout,
        get_saml2_query_request(request), next)

# Helpers

# SAMLv2 IdP settings variables
__local_options = getattr(settings, 'IDP_SAML2_METADATA_OPTIONS', {})
__user_backend_from_session = getattr(settings,
        'IDP_SAML2_AUTHN_CONTEXT_FROM_SESSION', True)
__delta = getattr(settings, 'IDP_SECONDS_TOLERANCE', 60)

# Mapping to generate the metadata file, must be kept in sync with the url
# dispatcher


def get_provider_id_and_options(request, provider_id):
    if not provider_id:
        provider_id = reverse(metadata)
    options = metadata_options
    options.update(__local_options)
    return provider_id, options


def get_metadata(request, provider_id=None):
    '''Generate the metadata XML file

       Metadata options can be overriden by setting IDP_METADATA_OPTIONS in
       settings.py.
    '''
    provider_id, options = get_provider_id_and_options(request, provider_id)
    return get_saml2_metadata(request, request.path, idp_map=metadata_map,
            options=metadata_options)


__cached_server = None


def create_server(request, provider_id=None):
    '''Build a lasso.Server object using current settings for the IdP

    The built lasso.Server is cached for later use it should work until
    multithreading is used, then thread local storage should be used.
    '''
    global __cached_server
    if __cached_server:
        # clear loaded providers
        __cached_server.providers = {}
        return __cached_server
    provider_id, options = get_provider_id_and_options(request, provider_id)
    __cached_server = create_saml2_server(request, provider_id,
            idp_map=metadata_map, options=options)
    return __cached_server


def log_info_authn_request_details(login):
    '''Push to logs details abour the received AuthnRequest'''
    request = login.request
    details = {'issuer': login.request.issuer and login.request.issuer.content,
            'forceAuthn': login.request.forceAuthn,
            'isPassive': login.request.isPassive,
            'protocolBinding': login.request.protocolBinding}
    nameIdPolicy = request.nameIdPolicy
    if nameIdPolicy:
        details['nameIdPolicy'] = {
                'allowCreate': nameIdPolicy.allowCreate,
                'format': nameIdPolicy.format,
                'spNameQualifier': nameIdPolicy.spNameQualifier}

    logger.info('%r' % details)


def check_destination(request, req_or_res):
    '''Check that a SAML message Destination has the proper value'''
    destination = request.build_absolute_uri(request.path)
    result = req_or_res.destination == destination
    if not result:
        logger.warning('failure, expected: %r got: %r ' \
            % (destination, req_or_res.destination))
    return result
