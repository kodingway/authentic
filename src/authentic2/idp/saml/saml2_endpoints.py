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
from functools import wraps

from authentic2.compat_lasso import lasso
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse, HttpResponseRedirect, \
    HttpResponseForbidden, HttpResponseBadRequest
from django.utils.translation import ugettext as _, ugettext_noop as N_
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.contrib.auth import BACKEND_SESSION_KEY, REDIRECT_FIELD_NAME
from django.conf import settings
from django.utils.encoding import smart_unicode
from django.contrib.auth import load_backend
from django.shortcuts import render, redirect
from django.contrib import messages


from authentic2.compat import get_user_model
import authentic2.views as a2_views
from authentic2.saml.models import (LibertyArtifact,
    LibertySession, LibertyFederation, 
    nameid2kwargs, saml2_urn_to_nidformat,
    nidformat_to_saml2_urn, save_key_values, get_and_delete_key_values,
    LibertyProvider, LibertyServiceProvider, SAMLAttribute, NAME_ID_FORMATS)
from authentic2.saml.common import redirect_next, asynchronous_bindings, \
    soap_bindings, load_provider, get_saml2_request_message, \
    error_page, set_saml2_response_responder_status_code, \
    AUTHENTIC_STATUS_CODE_MISSING_DESTINATION, \
    load_federation, \
    return_saml2_response, \
    get_soap_message, soap_fault, return_saml_soap_response, \
    AUTHENTIC_STATUS_CODE_UNKNOWN_PROVIDER, \
    AUTHENTIC_STATUS_CODE_MISSING_NAMEID, \
    AUTHENTIC_STATUS_CODE_MISSING_SESSION_INDEX, \
    AUTHENTIC_STATUS_CODE_UNKNOWN_SESSION, \
    AUTHENTIC_STATUS_CODE_INTERNAL_SERVER_ERROR, \
    AUTHENTIC_STATUS_CODE_UNAUTHORIZED, \
    send_soap_request, get_saml2_query_request, \
    get_saml2_request_message_async_binding, create_saml2_server, \
    get_saml2_metadata, get_sp_options_policy, \
    get_entity_id, AUTHENTIC_SAME_ID_SENTINEL
import authentic2.saml.saml2utils as saml2utils
from common import kill_django_sessions
from authentic2.constants import NONCE_FIELD_NAME

from authentic2.idp import signals as idp_signals

from authentic2.utils import (make_url, get_backends as get_idp_backends,
        get_username, login_require, find_authentication_event, datetime_to_xs_datetime)
from authentic2 import utils
from authentic2.attributes_ng.engine import get_attributes

from . import app_settings


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

def metadata(request):
    '''Endpoint to retrieve the metadata file'''
    logger = logging.getLogger(__name__)
    logger.info('return metadata')
    return HttpResponse(get_metadata(request, request.path),
            content_type='text/xml')

def log_assert(func, exception_classes=(AssertionError,)):
    '''Convert assertion errors to warning logs and report them to the user
       through the messages framework.

       Returns a redirect to homepage or the `next` query parameter.
    '''
    @wraps(func)
    def f(request, *args, **kwargs):
        try:
            return func(request, *args, **kwargs)
        except exception_classes, e:
            return error_redirect(request, e.message or repr(e))
    return f

#####
# SSO
#####
def register_new_saml2_session(request, login):
    '''Persist the newly created session for emitted assertion'''
    lib_session = LibertySession(provider_id=login.remoteProviderId,
            saml2_assertion=login.assertion,
            django_session_key=request.session.session_key)
    lib_session.save()


def fill_assertion(request, saml_request, assertion, provider_id, nid_format):
    '''Stuff an assertion with information extracted from the user record
       and from the session, and eventually from transactions linked to the
       request, i.e. a login event or a consent event.

       No check on the request must be done here, the sso method should have
       verified that the request can be answered and match any policy for the
       given provider or modified the request to match the identity provider
       policy.

    TODO: determine and add attributes from the session, for anonymous users
    (pseudonymous federation, openid without accounts)
    # TODO: add information from the login event, of the session or linked
    # to the request id
    # TODO: use information from the consent event to specialize release of
    # attributes (user only authorized to give its email for email)
       '''
    assert nid_format in NAME_ID_FORMATS

    logger = logging.getLogger(__name__)
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
        assert request.user.username, 'username field is required when using the username NameID format'
        assertion.subject.nameID.content = request.user.username.encode('utf-8')
    if nid_format == 'uuid':
        assertion.subject.nameID.content = request.user.uuid
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

def get_attribute_definitions(provider):
    '''Query all attribute definitions for a providers'''
    qs = SAMLAttribute.objects.for_generic_object(provider) \
            .filter(enabled=True)
    sp_options_policy = get_sp_options_policy(provider)
    if sp_options_policy:
        qs |= SAMLAttribute.objects.for_generic_object(sp_options_policy) \
                .filter(enabled=True)
    return qs.distinct()

def add_attributes(request, assertion, provider):
    qs = get_attribute_definitions(provider)
    wanted_attributes = [definition.attribute_name for definition in qs]

    ctx = get_attributes({
        'request': request,
        'user': request.user,
        'service': provider,
        '__wanted_attributes': wanted_attributes,
    })
    if not assertion.attributeStatement:
        assertion.attributeStatement = [lasso.Saml2AttributeStatement()]
    attribute_statement = assertion.attributeStatement[0]
    attributes = {}
    seen = set()
    # Keep current attributes, mark string values as already added
    for attribute in attribute_statement.attribute:
        name = attribute.name.decode('utf-8')
        name_format = attribute.nameFormat.decode('utf-8')
        attributes[(name, name_format)] = attribute, attribute.attributeValue
        for atv in attribute.attributeValue:
            if atv.any and len(atv.any) == 1 and isinstance(atv.any[0], lasso.MiscTextNode) and \
                    atv.any[0].textChild:
                seen.add((name, name_format, atv.any[0].content.decode('utf-8')))
    for definition in qs:
        name = definition.name
        name_format = definition.name_format_uri()
        friendly_name = definition.friendly_name
        if (name, name_format) in attributes:
            continue
        attribute, value = attributes[(name, name_format)] = lasso.Saml2Attribute(), []
        attribute.friendlyName = friendly_name.encode('utf-8')
        attribute.name = name.encode('utf-8')
        attribute.nameFormat = name_format.encode('utf-8')
    tuples = [tuple(t) for definition in qs for t in definition.to_tuples(ctx) ]
    seen = set()
    for name, name_format, friendly_name, value in tuples:
        # prevent repeating attribute values
        if (name, name_format, value) in seen:
            continue
        seen.add((name, name_format, value))
        attribute, values = attributes[(name, name_format)]

        # We keep only one friendly name
        if not attribute.friendlyName and friendly_name:
            attribute.friendlyName = friendly_name.encode('utf-8')
        atv = lasso.Saml2AttributeValue()
        tn = lasso.MiscTextNode.newWithString(value.encode('utf-8'))
        tn.textChild = True
        atv.any = [tn]
        values.append(atv)
    for attribute, values in attributes.itervalues():
        attribute.attributeValue = values
    attribute_statement.attribute = [attribute for attribute, values in attributes.itervalues()]

def saml2_add_attribute_values(assertion, attributes):
    logger = logging.getLogger(__name__)
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


def build_assertion(request, login, nid_format='transient'):
    """After a successfully validated authentication request, build an
       authentication assertion
    """
    logger = logging.getLogger(__name__)
    entity_id = get_entity_id(request, reverse(metadata))
    now = datetime.datetime.utcnow()
    logger.info("building assertion at %s" % str(now))
    logger.debug('named Id format is %s' % nid_format)
    # 1 minute ago
    notBefore = now - datetime.timedelta(0, app_settings.SECONDS_TOLERANCE)
    # 1 minute in the future
    notOnOrAfter = now + datetime.timedelta(0, app_settings.SECONDS_TOLERANCE)
    ssl = 'HTTPS' in request.environ
    if app_settings.AUTHN_CONTEXT_FROM_SESSION:
        backend = request.session[BACKEND_SESSION_KEY]
        logger.debug("authentication from session %s", backend)
        backend = load_backend(backend)
        if hasattr(backend, 'get_saml2_authn_context'):
            authn_context = backend.get_saml2_authn_context()
        else:
            raise Exception('backend unsupported: ' + backend)
        if authn_context == lasso.SAML2_AUTHN_CONTEXT_PASSWORD and ssl:
            authn_context = lasso.SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
    else:
        try:
            event = find_authentication_event(request, login.request.id)
            logger.debug("authentication from stored event %r", event)
            how = event['how']
            if how == 'password':
                authn_context = lasso.SAML2_AUTHN_CONTEXT_PASSWORD
            elif how == 'password-on-https':
                authn_context = \
                    lasso.SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
            elif how == 'ssl':
                authn_context = lasso.SAML2_AUTHN_CONTEXT_X509
            elif how.startswith('oath-totp'):
                authn_context = lasso.SAML2_AUTHN_CONTEXT_TIME_SYNC_TOKEN
            else:
                raise NotImplementedError('Unknown authentication method %s',
                        how)
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
    assertion.conditions.notOnOrAfter = notOnOrAfter.isoformat() + 'Z'
    # Set SessionNotOnOrAfter to expiry date of the current session, so we are sure no session on
    # service providers can outlive the IdP session.
    expiry_date = request.session.get_expiry_date()
    assertion.authnStatement[0].sessionNotOnOrAfter = datetime_to_xs_datetime(expiry_date)
    logger.debug("assertion building in progress %s" \
        % assertion.dump())
    logger.debug("fill assertion")
    fill_assertion(request, login.request, assertion, login.remoteProviderId,
        nid_format)
    # Save federation and new session
    if nid_format == 'persistent':
        logger.debug("nameID persistent, get or create "
            "federation")
        kwargs = nameid2kwargs(login.assertion.subject.nameID)
        # if qualifiers can be inferred from providers entityID replace them by
        # placeholders
        if kwargs.get('name_id_qualifier') == entity_id:
            kwargs['name_id_qualifier'] = AUTHENTIC_SAME_ID_SENTINEL
        if kwargs.get('name_id_sp_name_qualifier') == login.remoteProviderId:
            kwargs['name_id_sp_name_qualifier'] = AUTHENTIC_SAME_ID_SENTINEL
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
    logger.info(u'sending nameID %(name_id_format)r: %(name_id_content)r to '
                u'%(entity_id)s for user %(user)s' % kwargs)

    register_new_saml2_session(request, login)


@never_cache
@csrf_exempt
@log_assert
def sso(request):
    """Endpoint for receiving saml2:AuthnRequests by POST, Redirect or SOAP.
       For SOAP a session must be established previously through the login
       page. No authentication through the SOAP request is supported.
    """
    logger = logging.getLogger(__name__)
    logger.info("performing sso")
    if request.method == "GET":
        logger.debug('called by GET')
        consent_answer = request.GET.get('consent_answer', '')
        if consent_answer:
            logger.info(u'back from the consent page for federation with answer '
                        '%s', consent_answer)
    message = get_saml2_request_message(request)
    server = create_server(request)
    login = lasso.Login(server)
    # 1. Process the request, separate POST and GET treatment
    if not message:
        logger.warn("missing query string")
        return HttpResponseForbidden("A SAMLv2 Single Sign On request need a "
            "query string")
    logger.debug('processing sso request %r', message)
    policy = None
    signed = True
    while True:
        try:
            login.processAuthnRequestMsg(message)
            break
        except (lasso.ProfileInvalidMsgError,
            lasso.ProfileMissingIssuerError,), e:
            logger.warning('invalid message for WebSSO profile with '
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
            logger.warning("the request cannot be answered because no "
                "valid protocol binding could be found")
            login.response.status.statusMessage = 'No valid protocol binding could be found'
            return HttpResponseBadRequest(message)
        except lasso.ProviderMissingPublicKeyError, e:
            log_info_authn_request_details(login)
            logger.warning('no public key found: %s', e)
            login.response.status.statusMessage = 'The public key is unknown'
            return return_login_response(request, login)
        except lasso.DsError, e:
            log_info_authn_request_details(login)
            logger.warning('digital signature treatment error: %s', e)
            login.response.status.statusMessage = 'Signature validation failed'
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
                add_url = reverse('admin:saml_libertyprovider_add_from_url')
                add_url += '?' + urllib.urlencode({ 'entity_id': provider_id })
                return render(request,
                        'idp/saml/unknown_provider.html',
                        { 'entity_id': provider_id,
                          'add_url': add_url,
                        })
            else:
                policy = get_sp_options_policy(provider_loaded)
                if not policy:
                    return error_page(request, _('sso: No SP policy defined'),
                        logger=logger, warning=True)
                logger.info('provider %s loaded with success' \
                    % provider_id)
            if policy.authn_request_signed:
                verify_hint = lasso.PROFILE_SIGNATURE_VERIFY_HINT_FORCE
            else:
                verify_hint = lasso.PROFILE_SIGNATURE_VERIFY_HINT_IGNORE
                signed = False
            login.setSignatureVerifyHint(verify_hint)
    if signed and not check_destination(request, login.request):
        logger.warning('wrong or absent destination')
        return return_login_error(request, login,
                AUTHENTIC_STATUS_CODE_MISSING_DESTINATION)
    # Check NameIDPolicy or force the NameIDPolicy
    name_id_policy = login.request.nameIdPolicy
    if name_id_policy and \
            name_id_policy.format and \
            name_id_policy.format != \
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED:
        logger.debug('nameID policy is %r', name_id_policy.dump())
        nid_format = saml2_urn_to_nidformat(name_id_policy.format,
            accepted=policy.accepted_name_id_format)
        logger.debug('nameID format %s', nid_format)
        default_nid_format = policy.default_name_id_format
        logger.debug('default nameID format %s', default_nid_format)
        accepted_nid_format = policy.accepted_name_id_format
        logger.debug('nameID format accepted %s' \
            % str(accepted_nid_format))
        if (not nid_format or nid_format not in accepted_nid_format) and \
           default_nid_format != nid_format:
            set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_INVALID_NAME_ID_POLICY)
            logger.warning('NameID format required is not accepted')
            return finish_sso(request, login)
    else:
        logger.debug('no nameID policy format')
        nid_format = policy.default_name_id_format or 'transient'
        if not name_id_policy:
            logger.debug('no nameID policy at all')
            login.request.nameIdPolicy = lasso.Samlp2NameIDPolicy()
            name_id_policy = login.request.nameIdPolicy
        name_id_policy.format = NAME_ID_FORMATS[nid_format]['samlv2']
        logger.debug('set nameID policy format %s' % nid_format)
    return sso_after_process_request(request, login, nid_format=nid_format)


def need_login(request, login, nid_format):
    """Redirect to the login page with a nonce parameter to verify later that
       the login form was submitted
    """
    logger = logging.getLogger(__name__)
    nonce = login.request.id or get_nonce()
    save_key_values(nonce, login.dump(), False, nid_format)
    next_url = make_url(continue_sso, params={NONCE_FIELD_NAME: nonce})
    logger.debug('redirect to login page with next url %s', next_url)
    return login_require(request, next_url=next_url,
            params={NONCE_FIELD_NAME: nonce})


def get_url_with_nonce(request, function, nonce):
    url = reverse(function) + '?%s=%s' % (NONCE_FIELD_NAME, nonce)
    return urllib.quote(url)


def need_consent_for_federation(request, login, nid_format):
    logger = logging.getLogger(__name__)
    nonce = login.request.id or get_nonce()
    save_key_values(nonce, login.dump(), False, nid_format)
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
        % (reverse('a2-consent-federation'), NONCE_FIELD_NAME,
            nonce, get_url_with_nonce(request, continue_sso, nonce),
            display_name)
    logger.debug('redirect to url %s' % url)
    return HttpResponseRedirect(url)


@never_cache
def continue_sso(request):
    logger = logging.getLogger(__name__)
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
    try:
        login_dump, consent_obtained, nid_format = \
                get_and_delete_key_values(nonce)
    except KeyError:
        messages.warning(request, N_('request has expired'))
        return utils.redirect(request, 'auth_homepage')
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


def needs_persistence(nid_format):
    return nid_format not in ['transient', 'email', 'username', 'edupersontargetedid']


def sso_after_process_request(request, login, consent_obtained=False,
        consent_attribute_answer=False, user=None,
        nid_format='transient', return_profile=False):
    """Common path for sso and idp_initiated_sso.

       consent_obtained: whether the user has given his consent to this
       federation
       user: the user which must be federated, if None, current user is the
       default.
    """
    logger = logging.getLogger(__name__)
    nonce = login.request.id
    user = user or request.user
    did_auth = find_authentication_event(request, nonce) is not None
    force_authn = login.request.forceAuthn
    passive = login.request.isPassive

    logger.debug('named Id format is %s' \
        % nid_format)

    if not passive and \
            (user.is_anonymous() or (force_authn and not did_auth)):
        logger.info('login required')
        return need_login(request, login, nid_format)

    # No user is authenticated and passive is True, deny request
    if passive and user.is_anonymous():
        logger.info("%r - no user connected and passive request, returning "
                "NoPassive", nonce)
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_NO_PASSIVE)
        return finish_sso(request, login)

    #Do not ask consent for federation if a transient nameID is provided
    transient = False
    if nid_format == 'transient':
        transient = True

    decisions = idp_signals.authorize_service.send(sender=None,
         request=request, user=request.user, audience=login.remoteProviderId,
         attributes={})
    logger.info('signal authorize_service sent')

    # You don't dream. By default, access granted.
    # We catch denied decisions i.e. dic['authz'] = False
    access_granted = True
    for decision in decisions:
        logger.info('authorize_service connected '
            'to function %s' % decision[0].__name__)
        dic = decision[1]
        if dic and 'authz' in dic:
	    logger.info('decision is %s', dic['authz'])
            if 'message' in dic:
		logger.info(u'with message %s', unicode(dic['message']))
            if not dic['authz']:
                logger.info('access denied by an external function')
                access_granted = False
        else:
            logger.info('no function connected to authorize_service')

    if not access_granted:
        logger.info('access denied, return answer '
            'to the requester')
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_REQUEST_DENIED,
                msg=unicode(dic['message']))
        return finish_sso(request, login)

    provider = load_provider(request, login.remoteProviderId,
        server=login.server)
    if not provider:
        return error_page(request,
            _('Provider %s is unknown') % login.remoteProviderId,
            logger=logger)
    saml_policy = get_sp_options_policy(provider)
    if not saml_policy:
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

    logger = logging.getLogger(__name__)
    logger.debug('the user consent status before process is %s' \
        % str(consent_obtained))

    consent_value = None
    if consent_obtained:
        consent_value = 'urn:oasis:names:tc:SAML:2.0:consent:current-explicit'
    else:
        consent_value = 'urn:oasis:names:tc:SAML:2.0:consent:unavailable'

    if not consent_obtained and not transient:
        consent_obtained = \
                not saml_policy.ask_user_consent
        logger.debug('the policy says %s' \
            % str(consent_obtained))
        if consent_obtained:
            #The user consent is bypassed by the policy
            consent_value = 'urn:oasis:names:tc:SAML:2.0:consent:unspecified'

    if needs_persistence(nid_format):
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
        return need_consent_for_federation(request, login, nid_format)

    logger.debug(''
        'login dump before processing %s' % login.dump())
    try:
        if needs_persistence(nid_format):
            logger.debug('load identity dump')
            load_federation(request, get_entity_id(request, reverse(metadata)), login, user)
        login.validateRequestMsg(not user.is_anonymous(), consent_obtained)
        logger.debug('validateRequestMsg %s' \
            % login.dump())
    except lasso.LoginRequestDeniedError:
        logger.error('access denied due to LoginRequestDeniedError')
        set_saml2_response_responder_status_code(login.response,
            lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login, user=user)
    except lasso.LoginFederationNotFoundError:
        logger.error('access denied due to LoginFederationNotFoundError')
        set_saml2_response_responder_status_code(login.response,
                lasso.SAML2_STATUS_CODE_REQUEST_DENIED)
        return finish_sso(request, login, user=user)

    login.response.consent = consent_value

    build_assertion(request, login, nid_format=nid_format)
    add_attributes(request, login.assertion, provider)
    return finish_sso(request, login, user=user, return_profile=return_profile)


def return_login_error(request, login, error):
    """Set the first level status code to Responder, the second level to error
    and return the response message for the assertionConsumer"""
    logger = logging.getLogger(__name__)
    logger.debug('error %s' % error)
    set_saml2_response_responder_status_code(login.response, error)
    return return_login_response(request, login)


def return_login_response(request, login):
    '''Return the AuthnResponse message to the assertion consumer'''
    logger = logging.getLogger(__name__)
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


def finish_sso(request, login, user=None, return_profile=False):
    logger = logging.getLogger(__name__)
    logger.info('finishing sso...')
    if user is None:
        logger.debug('user is None')
        user = request.user
    response = return_login_response(request, login)
    logger.info('sso treatment ended, send response')
    if return_profile:
        return login
    return response


def save_artifact(request, login):
    '''Remember an artifact message for later retrieving'''
    logger = logging.getLogger(__name__)
    LibertyArtifact(artifact=login.artifact,
            content=login.artifactMessage.decode('utf-8'),
            provider_id=login.remoteProviderId).save()
    logger.debug('artifact saved')


def reload_artifact(login):
    logger = logging.getLogger(__name__)
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


@never_cache
@csrf_exempt
def artifact(request):
    '''Resolve a SAMLv2 ArtifactResolve request
    '''
    logger = logging.getLogger(__name__)
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
    logger = logging.getLogger(__name__)
    logger.info('superuser? %s' \
        % str(request.user.is_superuser()))
    return request.user.is_superuser()


@never_cache
@csrf_exempt
@login_required
def idp_sso(request, provider_id=None, return_profile=False):
    '''Initiate an SSO toward provider_id without a prior AuthnRequest
    '''
    logger = logging.getLogger(__name__)
    User = get_user_model()
    if not provider_id:
        provider_id = request.REQUEST.get('provider_id')
    if not provider_id:
        return error_redirect(request,
                N_('missing provider identifier'))
    logger.info('start of an idp initiated sso toward %r', provider_id)
    server = create_server(request)
    login = lasso.Login(server)
    liberty_provider = load_provider(request, provider_id,
        server=login.server)
    if not liberty_provider:
        return error_redirect(request, N_('provider %r is unknown'), provider_id)
    username = request.REQUEST.get('username')
    if username:
        if not check_delegated_authentication_permission(request):
            return error_redirect(request,
                    N_('%r tried to log as %r on %r but was forbidden'),
                   request.user, username, provider_id)
        try:
            user = User.objects.get_by_natural_key(username=username)
        except User.DoesNotExist:
            return error_redirect(request,
                    N_('you cannot login as %r as it does not exist'), username)
    else:
        user = request.user
    policy = get_sp_options_policy(liberty_provider)
    # Control assertion consumer binding
    if not policy:
        return error_redirect(request,
                N_('missing service provider policy'))
    nid_format = policy.default_name_id_format
    if needs_persistence(nid_format):
        load_federation(request, get_entity_id(request, reverse(metadata)), login, user)
    login.initIdpInitiatedAuthnRequest(provider_id)
    binding = policy.prefered_assertion_consumer_binding
    if binding == 'meta':
        pass
    elif binding == 'art':
        login.request.protocolBinding = lasso.SAML2_METADATA_BINDING_ARTIFACT
    elif binding == 'post':
        login.request.protocolBinding = lasso.SAML2_METADATA_BINDING_POST
    else:
        return error_redirect(request,
                N_('unknown binding %r') % binding)
    # Control nid format policy
    # XXX: if a federation exist, we should use transient
    login.request.nameIdPolicy.format = nidformat_to_saml2_urn(nid_format)
    login.request.nameIdPolicy.allowCreate = True

    login.processAuthnRequestMsg(None)
    logger.debug('nameId %r' % nid_format)
    logger.debug('binding %r' % binding)
    logger.info('authentication request initialized toward provider_id %r', provider_id)

    return sso_after_process_request(request, login,
            consent_obtained=False, user=user,
            nid_format=nid_format, return_profile=return_profile)


@never_cache
def finish_slo(request):
    logger = logging.getLogger(__name__)
    id = request.REQUEST.get('id')
    if not id:
        logger.error('missing id argument')
        return HttpResponseBadRequest('finish_slo: missing id argument')
    try:
        logout_dump, session_key = get_and_delete_key_values(id)
    except KeyError:
        messages.warning(request, N_('request has expired'))
        return utils.redirect(request, 'auth_homepage')
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
    logger = logging.getLogger(__name__)
    logout.buildResponseMsg()
    set_saml2_response_responder_status_code(logout.response, error)
    # Hack because response is not initialized before
    # buildResponseMsg
    logout.buildResponseMsg()
    logger.warning('returned an error message on logout: %s', error)
    provider = LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
    return return_saml2_response(request, logout,
        title=_('You are being redirected to "%s"') % provider.name)


def process_logout_request(request, message, binding):
    '''Do the first part of processing a logout request'''
    logger = logging.getLogger(__name__)
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
            policy = get_sp_options_policy(p)
            # we do not verify authn request, why verify logout requests...
            if not policy.authn_request_signed:
                logout.setSignatureVerifyHint(lasso.PROFILE_SIGNATURE_VERIFY_HINT_IGNORE)
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
    logger = logging.getLogger(__name__)
    name_id = nameid2kwargs(logout.request.nameId)
    session_indexes = logout.request.sessionIndexes
    logger.info('slo nameid: %s session_indexes: %s' \
        % (name_id, session_indexes))


def validate_logout_request(request, logout, idp=True):
    logger = logging.getLogger(__name__)
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
    logger = logging.getLogger(__name__)
    backends = get_idp_backends()
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


def get_only_last_session(issuer_id, provider_id, name_id, session_indexes):
    """Try to have a decent behaviour when receiving a logout request with
       multiple session indexes.

       Enumerate all emitted assertions for the given session, and for each
       provider only keep the more recent one.
    """
    logger = logging.getLogger(__name__)
    logger.debug('%s %s' % (name_id.dump(),
        session_indexes))
    lib_session1 = LibertySession.get_for_nameid_and_session_indexes(
            issuer_id, provider_id, name_id, session_indexes)
    django_session_keys = [s.django_session_key for s in lib_session1]
    lib_session = LibertySession.objects.filter(
            django_session_key__in=django_session_keys)
    providers = set([s.provider_id for s in lib_session])
    result = []
    for provider in providers:
        if provider != provider_id:
            x = lib_session.filter(provider_id=provider)
            latest = x.latest('creation')
            result.append(latest)
    if lib_session1:
        logger.debug('last session %s' % lib_session1)
    return lib_session1, result, django_session_keys


def build_session_dump(liberty_sessions):
    '''Build a session dump from a list of pairs
       (provider_id,assertion_content)'''
    logger = logging.getLogger(__name__)
    session = [u'<Session xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns="http://www.entrouvert.org/namespaces/lasso/0.0" Version="2">']
    for liberty_session in liberty_sessions:
        session.append(u'<NidAndSessionIndex ProviderID="{0.provider_id}" '
                       u'AssertionID="xxx" '
                       u'SessionIndex="{0.session_index}">'.format(liberty_session))
        session.append(u'<saml:NameID Format="{0.name_id_format}" '.format(liberty_session))
        if liberty_session.name_id_qualifier:
            session.append(u'NameQualifier="{0.name_id_qualifier}" '.format(liberty_session))
        if liberty_session.name_id_sp_name_qualifier:
            session.append(u'SPNameQualifier="{0.name_id_sp_name_qualifier}" '.format(liberty_session))
        session.append(u'>{0.name_id_content}</saml:NameID>'.format(liberty_session))
        session.append(u'</NidAndSessionIndex>')
    session.append(u'</Session>')
    s = ''.join(session)
    logger.debug('session built %s' % s)
    return s


def set_session_dump_from_liberty_sessions(profile, lib_sessions):
    '''Extract all assertion from a list of lib_sessions, and create a session
    dump from them'''
    logger = logging.getLogger(__name__)
    logger.debug('lib_sessions %s' \
        % lib_sessions)
    session_dump = build_session_dump(lib_sessions).encode('utf8')
    profile.setSessionFromDump(session_dump)
    logger.debug('profile %s' \
        % profile.session.dump())


@never_cache
@csrf_exempt
def slo_soap(request):
    """Endpoint for receiveing saml2:AuthnRequest by SOAP"""
    logger = logging.getLogger(__name__)
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
            get_only_last_session(logout.server.providerId,
                    logout.remoteProviderId, logout.request.nameId,
                    logout.request.sessionIndexes)
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


@never_cache
@csrf_exempt
def slo(request):
    """Endpoint for receiving SLO by POST, Redirect.
    """
    logger = logging.getLogger(__name__)
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
    except (lasso.ProfileInvalidMsgError,
        lasso.ProfileMissingIssuerError), e:
        return error_page(request, _('Invalid logout request'), logger=logger, warning=True)
    session_indexes = logout.request.sessionIndexes
    if len(session_indexes) == 0:
        logger.warning('slo received a request from %s without any \
            SessionIndex, it is forbidden' % logout.remoteProviderId)
        logout.buildResponseMsg()
        provider = LibertyProvider.objects.get(entity_id=logout.remoteProviderId)
        return return_saml2_response(request, logout,
            title=_('You are being redirected to "%s"') % provider.name)
    logger.info('asynchronous slo from %s' % logout.remoteProviderId)
    # Filter sessions
    all_sessions = LibertySession.get_for_nameid_and_session_indexes(
            logout.server.providerId, logout.remoteProviderId,
            logout.request.nameId, logout.request.sessionIndexes)
    if not all_sessions.exists():
        logger.warning('slo refused, since no session exists with the \
            requesting provider')
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_UNKNOWN_SESSION)
    # Load session dump for the requesting provider
    last_session = all_sessions.latest('creation')
    set_session_dump_from_liberty_sessions(logout, [last_session])
    try:
        logout.validateRequest()
    except lasso.Error, e:
        logger.warning('logout request validation failed: %s', e)
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_INTERNAL_SERVER_ERROR)
    except:
        logger.exception('internal error')
        return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_INTERNAL_SERVER_ERROR)
    # Now clean sessions for this provider
    LibertySession.objects.filter(provider_id=logout.remoteProviderId,
            django_session_key=request.session.session_key).delete()
    # Save some values for cleaning up
    save_key_values(logout.request.id, logout.dump(),
            request.session.session_key)

    # Use the logout view and come back to the finish slo view
    next_url = make_url(finish_slo, params={'id': logout.request.id})
    return a2_views.logout(request, next_url=next_url, do_local=False, check_referer=False)


def icon_url(name):
    return '%s/authentic2/images/%s.png' % (settings.STATIC_URL, name)

def ko_icon(request):
    return HttpResponseRedirect(icon_url('ko'))

def ok_icon(request):
    return HttpResponseRedirect(icon_url('ok'))


@never_cache
@csrf_exempt
@login_required
def idp_slo(request, provider_id=None):
    """Send a single logout request to a SP, if given a next parameter, return
    to this URL, otherwise redirect to an icon symbolizing failure or success
    of the request

    provider_id - entity id of the service provider to log out
    all - if present, logout all sessions by omitting the SessionIndex element
    """
    logger = logging.getLogger(__name__)
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
        return redirect_next(request, next) or ko_icon(request)
    logger.info('slo initiated with %(provider_id)s' \
        % {'provider_id': provider_id})

    server = create_server(request)
    logout = lasso.Logout(server)

    provider = load_provider(request, provider_id, server=logout.server)
    if not provider:
        logger.error('slo failed to load provider')
        return redirect_next(request, next) or ko_icon(request)
    policy = get_sp_options_policy(provider)
    if not policy:
        logger.error('No policy found for %s'\
             % provider_id)
        return redirect_next(request, next) or ko_icon(request)
    if not policy.forward_slo:
        logger.warn('slo asked for %s configured to not reveive '
            'slo' % provider_id)
        return redirect_next(request, next) or ko_icon(request)

    lib_sessions = LibertySession.objects.filter(
        django_session_key=request.session.session_key,
        provider_id=provider_id)
    if lib_sessions:
        logger.debug('%d lib_sessions found', lib_sessions.count())
        set_session_dump_from_liberty_sessions(logout, [lib_sessions[0]])
    try:
        logout.initRequest(provider_id, policy.http_method_for_slo_request)
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
    logger = logging.getLogger(__name__)
    logger.info('Response is %s' % str(soap_response))
    try:
        logout.processResponseMsg(soap_response)
    except getattr(lasso, 'ProfileRequestDeniedError', lasso.LogoutRequestDeniedError):
        logger.warning('%s denied the logout request', logout.remoteProviderId)
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


@never_cache
def slo_return(request):
    logger = logging.getLogger(__name__)
    logger.info('return from redirect')
    relay_state = request.REQUEST.get('RelayState')
    if not relay_state:
        return error_redirect(request, N_('slo no relay state in response'), 
                default_url=icon_url('ko'))
    logger.debug('relay_state %r', relay_state)
    try:
        logout_dump, provider_id, next = \
            get_and_delete_key_values(relay_state)
    except KeyError:
        return error_redirect(request,
                N_('unknown relay state %r'),
                relay_state,
                default_url=icon_url('ko'))
    server = create_server(request)
    logout = lasso.Logout.newFromDump(server, logout_dump)
    provider_id = logout.remoteProviderId
    # forced to reset signature_verify_hint as it is not saved in the dump
    provider = load_provider(request, provider_id, server=server)
    policy = get_sp_options_policy(provider)
    # FIXME: should use a logout_request_signature_check_hint
    if not policy.authn_request_signed:
        logout.setSignatureVerifyHint(lasso.PROFILE_SIGNATURE_VERIFY_HINT_IGNORE)
    if not load_provider(request, provider_id, server=logout.server):
        logger.warning('failed to load provider %r', provider_id)
    return process_logout_response(request, logout,
        get_saml2_query_request(request), next)

# Helpers

# Mapping to generate the metadata file, must be kept in sync with the url
# dispatcher

def get_provider_id_and_options(request, provider_id):
    if not provider_id:
        provider_id = reverse(metadata)
    options = {
            'key': app_settings.SIGNATURE_PUBLIC_KEY,
            'private_key': app_settings.SIGNATURE_PRIVATE_KEY,
    }
    options.update(app_settings.METADATA_OPTIONS)
    return provider_id, options


def get_metadata(request, provider_id=None):
    '''Generate the metadata XML file

       Metadata options can be overriden by setting IDP_METADATA_OPTIONS in
       settings.py.
    '''
    provider_id, options = get_provider_id_and_options(request, provider_id)
    return get_saml2_metadata(request, request.path, idp_map=metadata_map,
            options=options)


def create_server(request, provider_id=None):
    '''Build a lasso.Server object using current settings for the IdP

    The built lasso.Server is cached for later use it should work until
    multithreading is used, then thread local storage should be used.
    '''
    provider_id, options = get_provider_id_and_options(request, provider_id)
    __cached_server = create_saml2_server(request, provider_id,
            idp_map=metadata_map, options=options)
    return __cached_server


def log_info_authn_request_details(login):
    '''Push to logs details abour the received AuthnRequest'''
    logger = logging.getLogger(__name__)
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
    logger = logging.getLogger(__name__)
    destination = request.build_absolute_uri(request.path)
    result = req_or_res.destination == destination
    if not result:
        logger.warning('failure, expected: %r got: %r ',
            destination, req_or_res.destination)
    return result

def error_redirect(request, msg, *args, **kwargs):
    '''Log a warning message, register it with the messages framework, then
       redirect the user to the homepage.

       It will redirect to Authentic2 homepage unless a next query parameter was used.
    '''
    logger = logging.getLogger(__name__)
    default_kwargs = {
            'log_level': logging.WARNING,
            'msg_level': messages.WARNING,
            'default_url': None,
    }
    default_kwargs.update(kwargs)
    messages.add_message(request, default_kwargs['msg_level'], _(msg) % args)
    logger.log(default_kwargs['log_level'], msg, *args)
    next_url = request.GET.get(REDIRECT_FIELD_NAME)
    if next_url:
        return HttpResponseRedirect(next_url)
    default_url = kwargs.get('default_url')
    if default_url:
        return HttpResponseRedirect(default_url)
    else:
        return redirect('auth_homepage')
