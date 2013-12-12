"""SAML2.0 SP implementation"""

import logging
import urlparse

import lasso

from django.conf import settings
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect, \
    HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.template import RequestContext
from django.template.loader import render_to_string
from django.contrib.auth import login as auth_login, authenticate
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.translation import ugettext as _
from django.utils.http import urlquote

from authentic2.saml.common import get_idp_list, load_provider, \
    return_saml2_request, get_saml2_request_message, get_saml2_query_request, \
    get_saml2_post_response, soap_call, \
    lookup_federation_by_name_identifier, get_authorization_policy, \
    get_idp_options_policy, save_session, \
    add_federation, load_session, send_soap_request, \
    redirect_next, delete_session, SOAPException, \
    remove_liberty_session_sp, get_session_index, get_soap_message, \
    load_federation, save_manage, lookup_federation_by_user, \
    get_manage_dump, get_saml2_metadata, create_saml2_server, \
    maintain_liberty_session_on_service_provider, \
    get_session_not_on_or_after, \
    AUTHENTIC_STATUS_CODE_UNKNOWN_PROVIDER, \
    AUTHENTIC_STATUS_CODE_INTERNAL_SERVER_ERROR, \
    AUTHENTIC_STATUS_CODE_UNAUTHORIZED, \
    get_sp_options_policy, get_entity_id
from authentic2.saml.models import LibertyProvider, LibertyFederation, \
    LibertySessionSP, LibertySessionDump, LIBERTY_SESSION_DUMP_KIND_SP, \
    save_key_values, NAME_ID_FORMATS, LibertySession
from authentic2.saml.saml2utils import authnresponse_checking, \
    get_attributes_from_assertion
from authentic2.idp.saml.saml2_endpoints import return_logout_error
from authentic2.authsaml2.utils import error_page, register_next_target, \
    register_request_id, get_registered_url, save_federation_temp, \
    load_federation_temp
from authentic2.authsaml2 import signals
from authentic2.authsaml2.backends import AuthSAML2PersistentBackend
from authentic2.utils import cache_and_validate, flush_django_session

__logout_redirection_timeout = getattr(settings, 'IDP_LOGOUT_TIMEOUT', 600)

logger = logging.getLogger(__name__)

metadata_map = (
    ('AssertionConsumerService',
            lasso.SAML2_METADATA_BINDING_ARTIFACT,
            '/singleSignOnArtifact'),
    ('AssertionConsumerService',
            lasso.SAML2_METADATA_BINDING_POST,
            '/singleSignOnPost'),
    ('SingleLogoutService',
            lasso.SAML2_METADATA_BINDING_REDIRECT,
            '/singleLogout', '/singleLogoutReturn'),
    ('SingleLogoutService',
            lasso.SAML2_METADATA_BINDING_SOAP,
            '/singleLogoutSOAP'),
    ('ManageNameIDService',
            lasso.SAML2_METADATA_BINDING_SOAP,
            '/manageNameIdSOAP'),
    ('ManageNameIDService',
            lasso.SAML2_METADATA_BINDING_REDIRECT,
            '/manageNameId', '/manageNameIdReturn'),
)
metadata_options = {'key': settings.SAML_SIGNATURE_PUBLIC_KEY}
try:
    if settings.SHOW_DISCO_IN_MD:
        metadata_options['disco'] = ('/discoveryReturn', )
except:
    pass

@cache_and_validate(settings.LOCAL_METADATA_CACHE_TIMEOUT)
def metadata(request):
    '''Endpoint to retrieve the metadata file'''
    logger.info('metadata: return metadata')
    return HttpResponse(get_metadata(request, request.path),
            mimetype='text/xml')


##############################################################
#
# Discovery service Requester
# See Identity Provider Discovery Service Protocol and Profile
# OASIS Committee Specification 01
# 27 March 2008
#
##############################################################
def build_discovery_url(request):
    target = None
    returnIDParam = None
    try:
        target = settings.DISCO_SERVICE_NAME
        returnIDParam = settings.DISCO_RETURN_ID_PARAM
    except:
        logger.error('build_discovery_url: missing parameter in settings')
        return None
    _return = urlquote(request.build_absolute_uri(reverse(disco_response)))
    query = 'entityID=%s&return=%s&returnIDParam=%s' \
        % (urlquote(request.build_absolute_uri(reverse(metadata))),
            _return, returnIDParam)
    try:
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(target)
        return urlparse.urlunparse((scheme, netloc, path, params, query,
            fragment))
    except Exception, e:
        logger.error('build_discovery_url: Exception %s' % str(e))
        return None


def redirect_to_disco(request):
    register_next_target(request)
    url = build_discovery_url(request)
    if not url:
        return error_page(request,
            _('redirect_to_disco: unable to build disco request'),
                logger=logger)
    return HttpResponseRedirect(url)


def disco_response(request):
    if not request.method == "GET":
        message = _('disco_response: HTTP request not supported %s' \
            % request.method)
        return error_page(request, message, logger=logger)
    provider = request.GET.get(settings.DISCO_RETURN_ID_PARAM, '')
    if provider:
        request.session['prefered_idp'] = provider
        logger.info('disco_response: discovered %s' % provider)
    else:
        logger.warn('disco_response: No provider discovered')
    return HttpResponseRedirect(get_registered_url(request))


###
 # sso
 # @request
 # @entity_id: Provider ID to request
 #
 # Single SignOn request initiated from SP UI
 # Binding supported: Redirect
 ###
def sso(request, is_passive=None, force_authn=None, http_method=None):
    '''Django view initiating an AuthnRequesst toward an identity provider.

       Keyword arguments:
       entity_id -- the SAMLv2 entity id identifier targeted by the
       AuthnRequest, it should be resolvable to a metadata document.
       is_passive -- whether to let the identity provider passively, i.e.
       without user interaction, authenticate the user.
       force_authn -- whether to ask the identity provider to authenticate the
       user even if it is already authenticated.
    '''
    entity_id = request.REQUEST.get('entity_id')
    # 1. Save the target page
    logger.info('sso: save next url in session %s' \
        % request.session.session_key)
    register_next_target(request)

    # 2. Init the server object
    server = build_service_provider(request)
    if not server:
        return error_page(request,
            _('sso: Service provider not configured'), logger=logger)
    # 3. Define the provider or ask the user
    if not entity_id:
        providers_list = get_idp_list()
        if not providers_list:
            return error_page(request,
                 _('sso: Service provider not configured'), logger=logger)
        if providers_list.count() == 1:
            p = providers_list[0]
        else:
            logger.error('sso: No SAML2 identity provider selected')
            return error_page(request,
                _('sso: No SAML2 identity provider selected'),
                logger=logger)
    else:
        logger.info('sso: sso with provider %s' % entity_id)
        p = load_provider(request, entity_id, server=server, sp_or_idp='idp',
                autoload=True)
        if not p:
            return error_page(request,
                _('sso: The provider does not exist'), logger=logger)
    # 4. Build authn request
    login = lasso.Login(server)
    if not login:
        return error_page(request,
            _('sso: Unable to create Login object'), logger=logger)
    # Only redirect is necessary for the authnrequest
    if not http_method:
        http_method = server.getFirstHttpMethod(server.providers[p.entity_id],
                lasso.MD_PROTOCOL_TYPE_SINGLE_SIGN_ON)
        logger.debug('sso: \
            No http method given. Method infered: %s' % http_method)
    if http_method == lasso.HTTP_METHOD_NONE:
        return error_page(request,
            _('sso: %s does not have any supported SingleSignOn endpoint') \
            % entity_id, logger=logger)
    try:
        login.initAuthnRequest(p.entity_id, http_method)
    except lasso.Error, error:
        return error_page(request,
            _('sso: initAuthnRequest %s') % lasso.strError(error[0]),
            logger=logger)

    # 5. Request setting
    if not setAuthnrequestOptions(p, login, force_authn, is_passive):
        logger.error('sso: No policy defined')
        return error_page(request, _('sso: No IdP policy defined'),
            logger=logger)
    try:
        login.buildAuthnRequestMsg()
    except lasso.Error, error:
        return error_page(request,
            _('SSO: buildAuthnRequestMsg %s') % lasso.strError(error[0]),
            logger=logger)

    # 6. Save the request ID (association with the target page)
    logger.debug('sso: Authnrequest ID: %s' % login.request.iD)
    logger.debug('sso: Save request id in the session %s' \
        % request.session.session_key)
    register_request_id(request, login.request.iD)

    # 7. Redirect the user
    logger.debug('sso: user redirection')
    return return_saml2_request(request, login,
            title=('AuthnRequest for %s' % entity_id))


###
 # singleSignOnArtifact, singleSignOnPostOrRedirect
 # @request
 #
 # Single SignOn Response
 # Binding supported: Artifact, POST
 ###
def singleSignOnArtifact(request):
    logger.info('singleSignOnArtifact: Binding Artifact processing begins...')
    server = build_service_provider(request)
    if not server:
        return error_page(request,
            _('singleSignOnArtifact: Service provider not configured'),
            logger=logger)

    # Load the provider metadata using the artifact
    if request.method == 'GET':
        logger.debug('singleSignOnArtifact: GET')
        artifact = request.REQUEST.get('SAMLart')
    else:
        logger.debug('singleSignOnArtifact: POST')
        artifact = request.POST.get('SAMLart')
    logger.debug('singleSignOnArtifact: artifact %s' % artifact)
    p = LibertyProvider.get_provider_by_samlv2_artifact(artifact)
    p = load_provider(request, p.entity_id, server=server, sp_or_idp='idp')
    logger.info('singleSignOnArtifact: provider %s loaded' % p.entity_id)

    login = lasso.Login(server)
    if not login:
        return error_page(request,
            _('singleSignOnArtifact: Unable to create Login object'),
            logger=logger)

    message = get_saml2_request_message(request)
    if not message:
        return error_page(request,
            _('singleSignOnArtifact: No message given.'), logger=logger)
    #logger.debug('singleSignOnArtifact: message %s' % message)

    while True:
        logger.debug('singleSignOnArtifact: Authnresponse processing')
        try:
            if request.method == 'GET':
                login.initRequest(get_saml2_query_request(request),
                        lasso.HTTP_METHOD_ARTIFACT_GET)
            else:
                login.initRequest(artifact, lasso.HTTP_METHOD_ARTIFACT_POST)
            break
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError):
            logger.debug('singleSignOnArtifact: Unable to process \
                Authnresponse -load another provider')
            provider_id = login.remoteProviderId
            provider_loaded = load_provider(request, provider_id,
                    server=server, sp_or_idp='idp')

            if not provider_loaded:
                message = _('singleSignOnArtifact: provider %r unknown') \
                % provider_id
                return error_page(request, message, logger=logger)
            else:
                logger.info('singleSignOnArtifact: \
                    provider %s loaded' % provider_id)
                continue
        except lasso.Error, error:
            return error_page(request,
                _('singleSignOnArtifact: initRequest %s') \
                % lasso.strError(error[0]),
                logger=logger)

    try:
        login.buildRequestMsg()
    except lasso.Error, error:
        return error_page(request,
            _('singleSignOnArtifact: buildRequestMsg %s') \
            % lasso.strError(error[0]), logger=logger)

    # TODO: Client certificate
    client_cert = None
    try:
        logger.info('singleSignOnArtifact: soap call to %s' % login.msgUrl)
        logger.debug('singleSignOnArtifact: soap message %s' % login.msgBody)
        soap_answer = soap_call(login.msgUrl,
            login.msgBody, client_cert=client_cert)
    except Exception:
        return error_page(request,
            _('singleSignOnArtifact: Failure to communicate \
            with artifact resolver %r') % login.msgUrl,
            logger=logger)
    if not soap_answer:
        return error_page(request,
            _('singleSignOnArtifact: Artifact resolver at %r returned \
            an empty response') % login.msgUrl,
            logger=logger)

    logger.debug('singleSignOnArtifact: soap answer %s' % soap_answer)

    # If connexion over HTTPS, do not check signature?!
    if login.msgUrl.startswith('https'):
        logger.debug('singleSignOnArtifact: \
            artifact solved over HTTPS - Signature Hint forbidden')
        login.setSignatureVerifyHint(lasso.PROFILE_SIGNATURE_HINT_FORBID)

    try:
        login.processResponseMsg(soap_answer)
    except lasso.Error, error:
        return error_page(request,
            _('singleSignOnArtifact: processResponseMsg raised %s') \
            % lasso.strError(error[0]), logger=logger)

    # TODO: Relay State

    logger.info('singleSignOnArtifact: Binding artifact treatment terminated')
    return sso_after_response(request, login, provider=p)


@csrf_exempt
def singleSignOnPost(request):
    logger.info('singleSignOnPost: Binding POST processing begins...')
    server = build_service_provider(request)
    if not server:
        return error_page(request,
            _('singleSignOnPost: Service provider not configured'),
            logger=logger)

    login = lasso.Login(server)
    if not login:
        return error_page(request,
            _('singleSignOnPost: Unable to create Login object'),
            logger=logger)

    # TODO: check messages = get_saml2_request_message(request)

    # Binding POST
    message = get_saml2_post_response(request)
    if not message:
        return error_page(request,
            _('singleSignOnPost: No message given.'), logger=logger)
    logger.debug('singleSignOnPost: message %s' % message)

    ''' Binding REDIRECT

        According to: saml-profiles-2.0-os
        The HTTP Redirect binding MUST NOT be used,
        as the response will typically exceed the
        URL length permitted by most user agents.
    '''
    # if not message:
    #    message = request.META.get('QUERY_STRING', '')

    while True:
        logger.debug('singleSignOnPost: Authnresponse processing')
        try:
            login.processAuthnResponseMsg(message)
            break
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError):
            logger.debug('singleSignOnPost: \
                Unable to process Authnresponse - load another provider')
            provider_id = login.remoteProviderId
            provider_loaded = load_provider(request, provider_id,
                    server=server, sp_or_idp='idp', autoload=True)

            if not provider_loaded:
                message = _('singleSignOnPost: provider %r unknown' \
                    % provider_id)
                return error_page(request, message, logger=logger)
            else:
                logger.info('singleSignOnPost: \
                    provider %s loaded' % provider_id)
                continue
        except lasso.Error, error:
            logger.debug('singleSignOnPost: lasso error, login dump is %s' \
                % login.dump())
            return error_page(request,
                _('singleSignOnPost: %s') % lasso.strError(error[0]),
                logger=logger)

    logger.info('singleSignOnPost: Binding POST treatment terminated')
    return sso_after_response(request, login, provider=provider_loaded)


###
 # sso_after_response
 # @request
 # @login
 # @relay_state
 #
 # Post-authnrequest processing
 ###
def sso_after_response(request, login, relay_state=None, provider=None):
    logger.info('sso_after_response: Authnresponse processing begins...')

    subject_confirmation = request.build_absolute_uri().partition('?')[0]
    saml_request_id = request.session.get('saml_request_id')
    check = authnresponse_checking(login, subject_confirmation, logger, saml_request_id=saml_request_id)
    if not check:
        return error_page(request,
            _('sso_after_response: error checking authn response'), logger=logger)

    try:
        login.acceptSso()
    except lasso.Error, error:
        return error_page(request,
            _('sso_after_response: acceptSso raised %s') \
                % lasso.strError(error[0]), logger=logger)

    logger.info('sso_after_response: \
        Assertion processing terminated with success')

    attributes = get_attributes_from_assertion(login.assertion, logger)
    # Register attributes in session for other applications
    request.session['attributes'] = attributes

    attrs = {}

    for att_statement in login.assertion.attributeStatement:
        for attribute in att_statement.attribute:
            name = None
            format = lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC
            nickname = None
            try:
                name = attribute.name.decode('ascii')
            except:
                logger.warning('sso_after_response: error decoding name of \
                    attribute %s' % attribute.dump())
            else:
                try:
                    if attribute.nameFormat:
                        format = attribute.nameFormat.decode('ascii')
                    if attribute.friendlyName:
                        nickname = attribute.friendlyName
                except Exception, e:
                    message = 'sso_after_response: name or format of an \
                        attribute failed to decode as ascii: %s due to %s'
                    logger.warning(message % (attribute.dump(), str(e)))
                try:
                    if name:
                        if format:
                            if nickname:
                                key = (name, format, nickname)
                            else:
                                key = (name, format)
                        else:
                            key = (name)
                    attrs[key] = list()
                    for value in attribute.attributeValue:
                        content = [any.exportToXml() for any in value.any]
                        content = ''.join(content)
                        attrs[key].append(content.decode('utf8'))
                except Exception, e:
                    message = 'sso_after_response: value of an \
                        attribute failed to decode as ascii: %s due to %s'
                    logger.warning(message % (attribute.dump(), str(e)))

    if not 'multisource_attributes' in request.session:
        request.session['multisource_attributes'] = dict()
    request.\
        session['multisource_attributes'][login.assertion.issuer.content] = \
            list()
    a8n = dict()
    a8n['certificate_type'] = 'SAML2_assertion'
    try:
        a8n['nameid'] = \
            login.assertion.subject.nameID.content
    except:
        pass
    try:
        a8n['subject_confirmation_method'] = \
            login.assertion.subject.subjectConfirmation.method
    except:
        pass
    try:
        a8n['not_before'] = \
            login.assertion.subject. \
            subjectConfirmation.subjectConfirmationData.notBefore
    except:
        pass
    try:
        a8n['not_on_or_after'] = \
            login.assertion.subject.subjectConfirmation. \
            subjectConfirmationData.notOnOrAfter
    except:
        pass
    try:
        a8n['authn_context'] = \
            login.assertion.authnStatement[0]. \
            authnContext.authnContextClassRef
    except:
        pass
    try:
        a8n['authn_instant'] = \
            login.assertion.authnStatement[0].authnInstant
    except:
        pass
    a8n['attributes'] = attrs
    request.\
        session['multisource_attributes'][login.assertion.issuer.content].\
            append(a8n)
    logger.debug('sso_after_response: \
        attributes in assertion %s from %s' \
        % (str(attrs), login.assertion.issuer.content))
    #authncontext

    #Access control processing
    decisions = signals.authz_decision.send(sender=None,
         request=request, attributes=attributes, provider=provider)
    if not decisions:
        logger.debug('sso_after_response: No authorization function \
            connected')

    access_granted = True
    one_message = False
    for decision in decisions:
        logger.debug('sso_after_response: authorization function %s' \
            % decision[0].__name__)
        dic = decision[1]
        logger.debug('sso_after_response: decision is %s' % dic['authz'])
        if 'message' in dic:
            logger.debug('sso_after_response: with message %s' \
                % dic['message'])
        if not dic['authz']:
            access_granted = False
            if 'message' in dic:
                one_message = True
                messages.add_message(request, messages.ERROR, dic['message'])

    if not access_granted:
        if not one_message:
            p = get_authorization_policy(provider)
            messages.add_message(request, messages.ERROR,
                p.default_denial_message)
        return error_page(request,
            logger=logger, default_message=False, timer=True)

    #Access granted, now we deal with session management
    policy = get_idp_options_policy(provider)
    if not policy:
        logger.error('sso_after_response: No policy defined')
        return error_page(request,
            _('sso_after_response: No IdP policy defined'), logger=logger)

    user = request.user

    url = get_registered_url(request)
    if not 'saml_request_id' in request.session:
        #IdP initiated
        url = policy.back_url
    if login.nameIdentifier.format == \
        lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT \
        and (policy is None \
             or not policy.transient_is_persistent):
        logger.info('sso_after_response: Transient nameID')
        if policy.handle_transient == 'AUTHSAML2_UNAUTH_TRANSIENT_ASK_AUTH':
            if not request.user.is_authenticated():
                #XXX: To test!
                logger.info('sso_after_response: Account linking required')
                save_session(request, login,
                    kind=LIBERTY_SESSION_DUMP_KIND_SP)
                logger.debug('sso_after_response: \
                    Register identity dump in session')
                save_federation_temp(request, login, attributes=attributes)
                maintain_liberty_session_on_service_provider(request, login)
                return render_to_response('auth/saml2/account_linking.html',
                        context_instance=RequestContext(request))
            logger.debug('sso_after_response: django session opened')
            session_not_on_or_after = \
                get_session_not_on_or_after(login.assertion)
            if session_not_on_or_after:
                request.session.set_expiry(session_not_on_or_after)
                logger.debug('sso_after_response: session set to expire on \
                    %s by SessionNotOnOrAfter attribute',
                        session_not_on_or_after)
            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()
            save_session(request, login, kind=LIBERTY_SESSION_DUMP_KIND_SP)
            logger.info('sso_after_response: \
                login processing ended with success - redirect to target')
            return HttpResponseRedirect(url)

        if policy.handle_transient == \
                'AUTHSAML2_UNAUTH_TRANSIENT_OPEN_SESSION':
            logger.info('sso_after_response: \
                Opening session for transient with nameID')
            logger.debug('sso_after_response: nameID %s' \
                % login.nameIdentifier.dump())
            user = authenticate(name_id=login.nameIdentifier)
            if not user:
                return error_page(request,
                    _('sso_after_response: \
                    No backend for temporary federation is configured'),
                    logger=logger)
            auth_login(request, user)
            logger.debug('sso_after_response: django session opened')
            session_not_on_or_after = \
                get_session_not_on_or_after(login.assertion)
            if session_not_on_or_after:
                request.session.set_expiry(session_not_on_or_after)
                logger.debug('sso_after_response: session set to expire on \
                    %s by SessionNotOnOrAfter attribute',
                        session_not_on_or_after)
            signals.auth_login.send(sender=None,
                request=request, attributes=attributes)
            logger.debug('sso_after_response: successful login signal sent')
            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()
            save_session(request, login, kind=LIBERTY_SESSION_DUMP_KIND_SP)
            logger.info('sso_after_response: \
                login processing ended with success - redirect to target')
            return HttpResponseRedirect(url)
        return error_page(request, _('sso_after_response: \
            Transient access policy: Configuration error'),
            logger=logger)

    elif login.nameIdentifier.format != \
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT \
            or (policy is not None and policy.transient_is_persistent):
        #Consider that all kinds of nameId not transient are persistent.
        logger.info('sso_after_response: persistent federation processing')
        if policy is not None and policy.transient_is_persistent and \
                login.nameIdentifier.format == \
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT:
            logger.info('sso_after_response: \
                the nameId %s is transient the but option persistent '
                'federation processing is selected' \
                    % login.nameIdentifier.dump())
            if policy.persistent_identifier_attribute:
                logger.info('sso_after_response: '
                    '%s is used as persistent identifier for federation' % \
                    policy.persistent_identifier_attribute)
                identifier = None
                for key in attributes:
                    if policy.persistent_identifier_attribute in key \
                            and attributes[key]:
                        identifier = attributes[key][0]
                        break
                if identifier:
                    logger.info('sso_after_response: '
                        '%s value is %s' % \
                        (policy.persistent_identifier_attribute, identifier))
                    login.nameIdentifier.content = identifier
                else:
                    logger.warn('sso_after_response: '
                        '%s not provided by the identity provider, '
                        'we continue with the nameID.' % \
                        policy.persistent_identifier_attribute)
            else:
               logger.info('sso_after_response: '
                    'No attribute declared as persistent identifier '
                    'NameID is used.')
            login.nameIdentifier.format = \
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT
            login.nameIdentifier.nameQualifier = provider.entity_id

        user = AuthSAML2PersistentBackend(). \
            authenticate(name_id=login.nameIdentifier,
                provider_id=login.remoteProviderId)
        if not user and \
                policy.handle_persistent == \
                    'AUTHSAML2_UNAUTH_PERSISTENT_CREATE_USER_PSEUDONYMOUS':
            # Auto-create an user then do the authentication again
            logger.info('sso_after_response: Account creation')
            AuthSAML2PersistentBackend(). \
                create_user(name_id=login.nameIdentifier,
                    provider_id=provider.entity_id)
            user = AuthSAML2PersistentBackend(). \
                authenticate(name_id=login.nameIdentifier,
                    provider_id=login.remoteProviderId)
        if user:
            auth_login(request, user)
            logger.debug('sso_after_response: session opened')
            signals.auth_login.send(sender=None,
                request=request, attributes=attributes)
            logger.debug('sso_after_response: \
                signal sent that the session is opened')
            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()
            save_session(request, login, kind=LIBERTY_SESSION_DUMP_KIND_SP)
            maintain_liberty_session_on_service_provider(request, login)
            logger.info('sso_after_response: \
                Login processing ended with success - redirect to target')
            return HttpResponseRedirect(url)
        elif policy.handle_persistent == \
                'AUTHSAML2_UNAUTH_PERSISTENT_ACCOUNT_LINKING_BY_AUTH':
            '''Check if the user consent for federation has been given'''
            if policy.force_user_consent \
                    and not login.response.consent in \
                    ('urn:oasis:names:tc:SAML:2.0:consent:obtained',
                    'urn:oasis:names:tc:SAML:2.0:consent:prior',
                    'urn:oasis:names:tc:SAML:2.0:consent:current-explicit',
                    'urn:oasis:names:tc:SAML:2.0:consent:current-implicit'):
                return error_page(request, _('sso_after_response: You were \
                    not asked your consent for account linking'),
                    logger=logger)
            if request.user.is_authenticated():
                logger.info('sso_after_response: Add federation')
                add_federation(request.user, name_id=login.nameIdentifier,
                    provider_id=login.remoteProviderId)
                return HttpResponseRedirect(url)
            logger.info('sso_after_response: Account linking required')
            save_session(request, login, kind=LIBERTY_SESSION_DUMP_KIND_SP)
            logger.debug('sso_after_response: \
                Register identity dump in session')
            save_federation_temp(request, login, attributes=attributes)
            maintain_liberty_session_on_service_provider(request, login)
            return render_to_response('auth/saml2/account_linking.html',
                    context_instance=RequestContext(request))
        return error_page(request,
            _('sso_after_response: \
            Persistent Account policy: Configuration error'), logger=logger)

    return error_page(request,
        _('sso_after_response: \
        Transient access policy: NameId format not supported'), logger=logger)
        #TODO: Relay state


###
 # finish_federation
 # @request
 #
 # Called after an account linking.
 # TODO: add checkbox, create new account (settings option, user can choose)
 # Create pseudonymous or user choose or only account linking
 ###
@csrf_exempt
def finish_federation(request):
    logger.info('finish_federation: Return after account linking form filled')
    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            logger.info('finish_federation: form valid')
            server = build_service_provider(request)
            if not server:
                return error_page(request,
                    _('finish_federation: \
                    Service provider not configured'), logger=logger)

            login = lasso.Login(server)
            if not login:
                return error_page(request,
                    _('finish_federation: \
                    Unable to create Login object'), logger=logger)

            s = load_session(request, login, kind=LIBERTY_SESSION_DUMP_KIND_SP)
            load_federation_temp(request, login)
            if not login.session:
                return error_page(request,
                    _('finish_federation: Error loading session.'),
                    logger=logger)

            login.nameIdentifier = request.session['nameId']

            logger.debug('finish_federation: nameID %s' % \
                login.nameIdentifier.dump())

            provider_id = None
            if 'remoteProviderId' in request.session:
                provider_id = request.session['remoteProviderId']
            fed = add_federation(form.get_user(),
                name_id=login.nameIdentifier,
                provider_id=provider_id)
            if not fed:
                return error_page(request,
                    _('SSO/finish_federation: \
                    Error adding new federation for this user'),
                    logger=logger)

            logger.info('finish_federation: federation added')

            url = get_registered_url(request)
            auth_login(request, form.get_user())
            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()
            logger.debug('finish_federation: session opened')

            attributes = []
            if 'attributes' in request.session:
                attributes = request.session['attributes']
            signals.auth_login.send(sender=None,
                request=request, attributes=attributes)
            logger.debug('finish_federation: \
                signal sent that the session is opened')

            if s:
                s.delete()
            if login.session:
                login.session.isDirty = True
            if login.identity:
                login.identity.isDirty = True
            save_session(request, login, kind=LIBERTY_SESSION_DUMP_KIND_SP)
            maintain_liberty_session_on_service_provider(request, login)
            logger.info('finish_federation: \
                Login processing ended with success - redirect to target')
            return HttpResponseRedirect(url)
        else:
            # TODO: Error: login failed: message and count 3 attemps
            logger.warning('finish_federation: \
                form not valid - Try again! (Brute force?)')
            return render_to_response('auth/saml2/account_linking.html',
                    context_instance=RequestContext(request))
    else:
        return error_page(request,
            _('finish_federation: Unable to perform federation'),
            logger=logger)


'''
    Single Logout (SLO)

    Initiated by SP or by IdP with SOAP or with Redirect
'''


def ko_icon(request):
    return HttpResponseRedirect('%s/authentic2/images/ko.png' \
        % settings.STATIC_URL)


def ok_icon(request):
    return HttpResponseRedirect('%s/authentic2/images/ok.png' \
        % settings.STATIC_URL)


def sp_slo(request, provider_id=None):
    '''
        To make another module call the SLO function.
        Does not deal with the local django session.
    '''
    next = request.REQUEST.get('next')

    logger.debug('sp_slo: provider_id in parameter %s' % str(provider_id))

    if request.method == 'GET' and 'provider_id' in request.GET:
        provider_id = request.GET.get('provider_id')
        logger.debug('sp_slo: provider_id from GET %s' % str(provider_id))
    if request.method == 'POST' and 'provider_id' in request.POST:
        provider_id = request.POST.get('provider_id')
        logger.debug('sp_slo: provider_id from POST %s' % str(provider_id))
    if not provider_id:
        logger.info('sp_slo: to initiate a slo we need a provider_id')
        return redirect_next(request, next) or ko_icon(request)
    logger.info('sp_slo: slo initiated with %(provider_id)s' \
        % {'provider_id': provider_id})

    server = create_server(request)
    logout = lasso.Logout(server)
    logger.info('sp_slo: sp_slo for %s' % provider_id)
    load_session(request, logout, kind=LIBERTY_SESSION_DUMP_KIND_SP)
    provider = load_provider(request, provider_id,
        server=server, sp_or_idp='idp')
    if not provider:
        logger.error('sp_slo: sp_slo failed to load provider')
        return redirect_next(request, next) or ko_icon(request)
    policy = get_idp_options_policy(provider)
    if not policy:
        logger.error('sp_slo: No policy found for %s'\
             % provider_id)
        return redirect_next(request, next) or ko_icon(request)
    if not policy.forward_slo:
        logger.warn('sp_slo: slo asked for %s configured to not receive slo' \
             % provider_id)
        return redirect_next(request, next) or ko_icon(request)
    if policy.enable_http_method_for_slo_request \
            and policy.http_method_for_slo_request:
        if policy.http_method_for_slo_request == lasso.HTTP_METHOD_SOAP:
            logger.info('sp_slo: sp_slo by SOAP')
            try:
                logout.initRequest(None, lasso.HTTP_METHOD_SOAP)
            except:
                logger.exception('sp_slo: sp_slo init error')
                return redirect_next(request, next) or ko_icon(request)
            try:
                logout.buildRequestMsg()
            except:
                logger.exception('sp_slo: sp_slo build error')
                return redirect_next(request, next) or ko_icon(request)
            try:
                soap_response = send_soap_request(request, logout)
            except:
                logger.exception('sp_slo: sp_slo SOAP failure')
                return redirect_next(request, next) or ko_icon(request)
            logger.info('sp_slo: successful soap call')
            return process_logout_response(request,
                logout, soap_response, next)
        else:
            try:
                logout.initRequest(None, lasso.HTTP_METHOD_REDIRECT)
            except:
                logger.exception('sp_slo: sp_slo init error')
                return redirect_next(request, next) or ko_icon(request)
            logout.msgRelayState = logout.request.id
            try:
                logout.buildRequestMsg()
            except:
                logger.exception('sp_slo: sp_slo build error')
                return redirect_next(request, next) or ko_icon(request)
            logger.info('sp_slo: sp_slo by redirect')
            save_key_values(logout.request.id,
                logout.dump(), provider_id, next)
            return HttpResponseRedirect(logout.msgUrl)
    try:
        logout.initRequest(provider_id)
    except lasso.ProfileMissingAssertionError:
        logger.error('sp_slo: \
            sp_slo failed because no sessions exists for %r' % provider_id)
        return redirect_next(request, next) or ko_icon(request)
    logout.msgRelayState = logout.request.id
    try:
        logout.buildRequestMsg()
    except:
        logger.exception('sp_slo: sp_slo misc error')
        return redirect_next(request, next) or ko_icon(request)
     # SOAP case
    if logout.msgBody:
        logger.info('sp_slo: sp_slo by SOAP')
        try:
            soap_response = send_soap_request(request, logout)
        except:
            logger.exception('sp_slo: sp_slo SOAP failure')
            return redirect_next(request, next) or ko_icon(request)
        return process_logout_response(request, logout, soap_response, next)
    else:
        logger.info('sp_slo: sp_slo by redirect')
        save_key_values(logout.request.id, logout.dump(), provider_id, next)
        return HttpResponseRedirect(logout.msgUrl)


def process_logout_response(request, logout, soap_response, next):
    try:
        logout.processResponseMsg(soap_response)
    except:
        logger.exception('process_logout_response: \
            processResponseMsg raised an exception')
        return redirect_next(request, next) or ko_icon(request)
    else:
        delete_session(request)
        return redirect_next(request, next) or ok_icon(request)


def localLogout(request, error):
    remove_liberty_session_sp(request)
    signals.auth_logout.send(sender=None, user=request.user)
    auth_logout(request)
    if hasattr(error, 'url'):
        return error_page(request,
            _('localLogout:  SOAP error \
            with %s - Only local logout performed.') % error.url,
            logger=logger)
    return error_page(request,
        _('localLogout:  %s -  Only local \
        logout performed.') % lasso.strError(error[0]),
        logger=logger)


def singleLogoutReturn(request):
    '''
        IdP response to a SLO SP initiated by redirect
    '''
    server = build_service_provider(request)
    if not server:
        return error_page(request,
            _('singleLogoutReturn: Service provider not configured'),
            logger=logger)

    query = get_saml2_query_request(request)
    if not query:
        return error_page(request,
            _('singleLogoutReturn: \
            Unable to handle Single Logout by Redirect without request'),
            logger=logger)

    logout = lasso.Logout(server)
    if not logout:
        return error_page(request,
            _('singleLogoutReturn: Unable to create Login object'),
            logger=logger)

    load_session(request, logout, kind=LIBERTY_SESSION_DUMP_KIND_SP)

    return slo_return(request, logout, query)


def slo_return(request, logout, message):
    try:
        logout.processResponseMsg(message)
    except lasso.Error:
        # Silent local logout
        return local_logout(request)
    if logout.isSessionDirty:
        if logout.session:
            save_session(request, logout, kind=LIBERTY_SESSION_DUMP_KIND_SP)
        else:
            delete_session(request)
    remove_liberty_session_sp(request)
    return local_logout(request)


def local_logout(request):
    global __logout_redirection_timeout
    "Logs out the user and displays 'You are logged out' message."
    context = RequestContext(request)
    context['redir_timeout'] = __logout_redirection_timeout
    context['message'] = 'You are logged out'
    template = 'auth/saml2/logout.html'
    context['next_page'] = '/'
    signals.auth_logout.send(sender=None, user=request.user)
    auth_logout(request)
    return render_to_response(template, context_instance=context)


def slo_soap_as_idp(request, logout, session=None):
    logger.debug('slo_soap_as_idp: start slo proxying to sp processing')
    from authentic2.idp.saml import saml2_endpoints
    error = saml2_endpoints. \
        validate_logout_request(request, logout, idp=False)
    if error:
        return error
    if not session:
        key = request.session.session_key
    else:
        key = session.django_session_key
    lib_sessions = LibertySession.objects.filter(
            django_session_key=key)
    if not lib_sessions:
        logger.debug('slo_soap_as_idp: no sp session')
    else:
        server = saml2_endpoints.create_server(request)
        logout2 = lasso.Logout(server)
        for lib_session in lib_sessions:
            logger.info('slo_soap_as_idp: logout to provider %s' \
                % lib_session.provider_id)
            p = load_provider(request, lib_session.provider_id,
                    server=server)
            if p:
                policy = get_sp_options_policy(p)
                if not policy:
                    logger.error('slo_soap_as_idp: No policy found for %s' \
                        % lib_session.provider_id)
                elif not policy.forward_slo:
                    logger.info('slo_soap_as_idp: %s configured to not \
                        reveive slo' % lib_session.provider_id)
                else:
                    try:
                        session_dump = saml2_endpoints.build_session_dump([lib_session])
                        logout2.setSessionFromDump(session_dump.encode('utf8'))
                        logout2.initRequest(None, lasso.HTTP_METHOD_SOAP)
                        logout2.buildRequestMsg()
                        soap_response = send_soap_request(request, logout2)
                    except Exception, e:
                        logger.error('slo_soap_as_idp: error building \
                            request to provider %s due to %s' \
                            % (lib_session.provider_id, str(e)))
                    else:
                        try:
                            logout2.processResponseMsg(soap_response)
                        except Exception, e:
                            logger.error('slo_soap_as_idp: error received \
                                from provider %s due to %s' \
                                % (lib_session.provider_id, str(e)))
            else:
                logger.error('slo_soap_as_idp: unable to load provider %s' \
                    % lib_session.provider_id)
    logger.debug('slo_soap_as_idp: end slo proxying to sp processing')


@csrf_exempt
def singleLogoutSOAP(request):
    '''
         Single Logout IdP initiated by SOAP
    '''
    try:
        soap_message = get_soap_message(request)
    except:
        return http_response_bad_request('singleLogoutSOAP: Bad SOAP message')

    if not soap_message:
        return http_response_bad_request('singleLogoutSOAP: Bad SOAP message')

    request_type = lasso.getRequestTypeFromSoapMsg(soap_message)
    if request_type != lasso.REQUEST_TYPE_LOGOUT:
        return http_response_bad_request('singleLogoutSOAP: \
        SOAP message is not a slo message')

    server = build_service_provider(request)
    if not server:
        return http_response_forbidden_request('singleLogoutSOAP: \
        Service provider not configured')

    logout = lasso.Logout(server)
    if not logout:
        return http_response_forbidden_request('singleLogoutSOAP: \
        Unable to create Logout object')

    provider_loaded = None
    while True:
        try:
            logout.processRequestMsg(soap_message)
            break
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError):
            provider_id = logout.remoteProviderId
            provider_loaded = load_provider(request, provider_id,
                    server=server, sp_or_idp='idp')

            if not provider_loaded:
                logger.warn('singleLogoutSOAP: provider %r unknown' \
                    % provider_id)
                return return_logout_error(request, logout,
                        AUTHENTIC_STATUS_CODE_UNKNOWN_PROVIDER)
            else:
                continue
        except lasso.Error, error:
            return return_logout_error(request, logout,
                AUTHENTIC_STATUS_CODE_INTERNAL_SERVER_ERROR)

    policy = get_idp_options_policy(provider_loaded)
    if not policy:
        logger.error('singleLogout: No policy found for %s'\
             % logout.remoteProviderId)
        return return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_UNAUTHORIZED)
    if not policy.accept_slo:
        logger.warn('singleLogout: received slo from %s not authorized'\
             % logout.remoteProviderId)
        return return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_UNAUTHORIZED)

    # Look for a session index
    try:
        session_index = logout.request.sessionIndex
    except:
        pass

    fed = lookup_federation_by_name_identifier(profile=logout)
    if not fed:
        logger.warning('singleLogoutSOAP: unknown user for %s' \
            % logout.request.dump())
        return logout, return_logout_error(request, logout,
                lasso.LOGOUT_ERROR_FEDERATION_NOT_FOUND)

    session = None
    if session_index:
#        # Map session.id to session.index
#        for x in get_session_manager().values():
#            if logout.remoteProviderId is x.proxied_idp:
#                if x._proxy_session_index == session_index:
#                   session = x
#            else:
#                if x.get_session_index() == session_index:
#                    session = x
        # TODO: WARNING: A user can be logged without a federation!
        try:
            session = LibertySessionSP. \
                objects.get(federation=fed, session_index=session_index)
        except:
            pass
        #XXX: deal with the session index
#    else:
#        # No session index take the last session
#        # with the same name identifier
#        name_identifier = logout.nameIdentifier.content
#        for session_candidate in get_session_manager().values():
#            if name_identifier in (session_candidate.name_identifiers or []):
#                session = session_candidate

    if session:
        q = LibertySessionDump. \
            objects.filter(django_session_key=session.django_session_key)
        if not q:
            logger.warning('singleLogoutSOAP: \
                No session dump for this session')
            return logout, return_logout_error(request, logout,
                    lasso.LOGOUT_ERROR_UNKNOWN_PRINCIPAL)
        logger.info('singleLogoutSOAP from %s, \
            for session index %s and session %s' % \
            (logout.remoteProviderId, session_index, session.id))
        try:
            #XXX: manage creation = models.DateTimeField(auto_now_add=True)
            #to user q.latest('creation')
            logout.setSessionFromDump(q[0].session_dump.encode('utf8'))
        except:
            q.delete()
            logger.error('singleLogoutSOAP: unable to set session from dump')
            return logout, return_logout_error(request, logout,
                    lasso.LOGOUT_ERROR_UNKNOWN_PRINCIPAL)
        q.delete()
    else:
        logger.warning('singleLogoutSOAP: No Liberty session found')
        return logout, return_logout_error(request, logout,
                lasso.LOGOUT_ERROR_UNKNOWN_PRINCIPAL)

    try:
        logout.validateRequest()
    except lasso.Error, error:
        message = 'singleLogoutSOAP validateRequest: %s' \
            % lasso.strError(error[0])
        logger.info(message)
        # We continue the process

    '''
        Play the role of IdP sending a SLO to all SP
    '''
    slo_soap_as_idp(request, logout, session)

    '''Break local session and respond to the IdP initiating the SLO'''

    try:
        flush_django_session(session.django_session_key)
        session.delete()
    except Exception, e:
        logger.error('singleLogoutSOAP: Error at session deletion due to %s' \
            % str(e))
        return finishSingleLogoutSOAP(logout)
    return finishSingleLogoutSOAP(logout)


def finishSingleLogoutSOAP(logout):
    try:
        logout.buildResponseMsg()
    except lasso.Error, error:
        message = 'singleLogoutSOAP \
            buildResponseMsg: %s' % lasso.strError(error[0])
        return http_response_forbidden_request(message)
    django_response = HttpResponse()
    django_response.status_code = 200
    django_response.content_type = 'text/xml'
    django_response.content = logout.msgBody
    return django_response


def singleLogout(request):
    '''
        Single Logout IdP initiated by Redirect
    '''
    query = get_saml2_query_request(request)
    if not query:
        return http_response_forbidden_request('singleLogout: \
            Unable to handle Single Logout by Redirect without request')

    server = build_service_provider(request)
    if not server:
        return http_response_forbidden_request('singleLogout: \
            Service provider not configured')

    logout = lasso.Logout(server)
    provider_loaded = None
    while True:
        try:
            logout.processRequestMsg(query)
            break
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError):
            provider_id = logout.remoteProviderId
            provider_loaded = load_provider(request, provider_id,
                    server=server, sp_or_idp='idp')

            if not provider_loaded:
                message = _('singleLogout: provider %r unknown') % provider_id
                return error_page(request, message, logger=logger)
            else:
                continue
        except lasso.Error, error:
            logger.error('singleLogout: %s' % lasso.strError(error[0]))
            return slo_return_response(logout)

    logger.info('singleLogout: from %s' % logout.remoteProviderId)

    policy = get_idp_options_policy(provider_loaded)
    if not policy:
        logger.error('singleLogout: No policy found for %s'\
             % logout.remoteProviderId)
        return return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_UNAUTHORIZED)
    if not policy.accept_slo:
        logger.warn('singleLogout: received slo from %s not authorized'\
             % logout.remoteProviderId)
        return return_logout_error(request, logout,
            AUTHENTIC_STATUS_CODE_UNAUTHORIZED)

    load_session(request, logout, kind=LIBERTY_SESSION_DUMP_KIND_SP)

    try:
        logout.validateRequest()
    except lasso.Error, error:
        logger.error('singleLogout: %s' % lasso.strError(error[0]))
        return slo_return_response(logout)

    #Play the role of IdP sending a SLO to all SP
    slo_soap_as_idp(request, logout)

    #Break local session and respond to the IdP initiating the SLO
    if logout.isSessionDirty:
        if logout.session:
            save_session(request, logout, kind=LIBERTY_SESSION_DUMP_KIND_SP)
        else:
            delete_session(request)
    remove_liberty_session_sp(request)
    signals.auth_logout.send(sender=None, user=request.user)
    auth_logout(request)
    return slo_return_response(logout)


def slo_return_response(logout):
    try:
        logout.buildResponseMsg()
    except lasso.Error, error:
        return http_response_forbidden_request('slo_return_response: %s') \
            % lasso.strError(error[0])
    else:
        logger.info('slo_return_response: redirect to %s' % logout.msgUrl)
        return HttpResponseRedirect(logout.msgUrl)


###
 # federationTermination
 # @request
 # @method
 # @entity_id
 #
 # Name Identifier Management
 # Federation termination: request from user interface
 # Profile supported: Redirect, SOAP
 # For response, if the requester uses a (a)synchronous binding,
 # the responder uses the same.
 # Else, the grabs the preferred method from the metadata.
 # By default we do not break the session.
 # TODO: Define in admin a parameter to indicate if the
 # federation termination implies a local logout (IDP and SP initiated)
 # -> Should not logout.
 # TODO: Clean tables of all dumps about this user
 ###
def federationTermination(request):
    entity_id = request.REQUEST.get('entity_id')
    if not entity_id:
        return error_page(request,
            _('fedTerm/SP UI: No provider for defederation'),
            logger=logger)

    if request.user.is_anonymous():
        return error_page(request,
            _('fedTerm/SP UI: Unable to defederate a not logged user!'),
            logger=logger)

    server = build_service_provider(request)
    if not server:
        error_page(request,
            _('fedTerm/SP UI: Service provider not configured'),
            logger=logger)

    # Lookup for the Identity provider
    p = load_provider(request, entity_id, server=server, sp_or_idp='idp')
    if not p:
        return error_page(request,
            _('fedTerm/SP UI: No such identity provider.'),
            logger=logger)

    manage = lasso.NameIdManagement(server)

    load_session(request, manage, kind=LIBERTY_SESSION_DUMP_KIND_SP)
    load_federation(request, get_entity_id(request, reverse(metadata)), manage)
    fed = lookup_federation_by_user(request.user, p.entity_id)
    if not fed:
        return error_page(request,
            _('fedTerm/SP UI: Not a valid federation'),
            logger=logger)

    # The user asks a defederation,
    # we perform without knowing if the IdP can handle
    fed.delete()

    # TODO: Deal with identity provider configuration in policies

    # If not defined in the metadata,
    # put ANY to let lasso do its job from metadata
    if not p.identity_provider.enable_http_method_for_defederation_request:
        try:
            manage.initRequest(entity_id, None, lasso.HTTP_METHOD_ANY)
        except lasso.Error, error:
            return error_page(request,
                _('fedTerm/SP UI: %s') % lasso.strError(error[0]),
                logger=logger)

        if manage.msgBody:
            try:
                manage.buildRequestMsg()
            except lasso.Error, error:
                return error_page(request,
                    _('fedTerm/SP SOAP: %s') % lasso.strError(error[0]),
                    logger=logger)
            # TODO: Client cert
            client_cert = None
            try:
                soap_answer = soap_call(manage.msgUrl,
                    manage.msgBody, client_cert=client_cert)
            except SOAPException:
                return error_page(request,
                    _('fedTerm/SP SOAP: \
                    Unable to perform SOAP defederation request'),
                    logger=logger)
            return manage_name_id_return(request, manage, soap_answer)
        else:
            try:
                manage.buildRequestMsg()
            except lasso.Error, error:
                return error_page(request,
                    _('fedTerm/SP Redirect: %s') % \
                    lasso.strError(error[0]), logger=logger)
            save_manage(request, manage)
            return HttpResponseRedirect(manage.msgUrl)

    # Else, taken from config
    if p.identity_provider.http_method_for_defederation_request == \
            lasso.HTTP_METHOD_SOAP:
        try:
            manage.initRequest(entity_id, None, lasso.HTTP_METHOD_SOAP)
            manage.buildRequestMsg()
        except lasso.Error, error:
            return error_page(request,
                _('fedTerm/SP SOAP: %s') % lasso.strError(error[0]),
                logger=logger)
        # TODO: Client cert
        client_cert = None
        try:
            soap_answer = soap_call(manage.msgUrl,
                manage.msgBody, client_cert=client_cert)
        except SOAPException:
            return error_page(request,
                _('fedTerm/SP SOAP: \
                Unable to perform SOAP defederation request'),
                logger=logger)
        return manage_name_id_return(request, manage, soap_answer)

    if p.identity_provider.http_method_for_defederation_request == \
            lasso.HTTP_METHOD_REDIRECT:
        try:
            manage.initRequest(entity_id, None, lasso.HTTP_METHOD_REDIRECT)
            manage.buildRequestMsg()
        except lasso.Error, error:
            return error_page(request,
                _('fedTerm/SP Redirect: %s') % lasso.strError(error[0]),
                logger=logger)
        save_manage(request, manage)
        return HttpResponseRedirect(manage.msgUrl)

    return error_page(request, _('Unknown HTTP method.'), logger=logger)


###
 # manageNameIdReturn
 # @request
 #
 # Federation termination: response from Redirect SP initiated
 ###
def manageNameIdReturn(request):
    server = build_service_provider(request)
    if not server:
        return error_page(request,
            _('fedTerm/SP Redirect: Service provider not configured'),\
            logger=logger)

    manage_dump = get_manage_dump(request)
    manage = None
    if manage_dump.exists() and manage_dump.count() > 1:
        manage_dump.delete()
        return error_page(request,
            _('fedTerm/SP Redirect: Error managing manage dump'),
            logger=logger)
    elif manage_dump.exists():
        try:
            manage = \
                lasso.NameIdManagement.newFromDump(server,
                manage_dump[0].manage_dump)
        except:
            pass
        manage_dump.delete()
    else:
        manage = lasso.NameIdManagement(server)

    if not manage:
        return error_page(request,
            _('fedTerm/SP Redirect: Defederation failed'), logger=logger)

    load_federation(request, get_entity_id(request, reverse(metadata)), manage)
    message = get_saml2_request_message(request)
    return manage_name_id_return(request, manage, message)


###
 # manage_name_id_return
 # @request
 # @logout
 # @message
 #
 # Post-response processing
 ###
def manage_name_id_return(request, manage, message):
    while True:
        try:
            manage.processResponseMsg(message)
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError):
            provider_id = manage.remoteProviderId
            provider_loaded = load_provider(request, provider_id,
                    server=manage.server, sp_or_idp='idp')

            if not provider_loaded:
                message = _('fedTerm/Return: \
                    provider %r unknown') % provider_id
                return error_page(request, message, logger=logger)
            else:
                continue
        except lasso.Error, error:
            return error_page(request,
                _('fedTerm/manage_name_id_return: %s') % \
                lasso.strError(error[0]),
                logger=logger)
    return HttpResponseRedirect(get_registered_url(request))


###
 # manageNameIdSOAP
 # @request
 #
 # Federation termination: request from SOAP IdP initiated
 # TODO: Manage valid soap responses on error (else error 500)
 ###
@csrf_exempt
def manageNameIdSOAP(request):
    try:
        soap_message = get_soap_message(request)
    except:
        return http_response_bad_request('fedTerm/IdP SOAP: Bad SOAP message')
    if not soap_message:
        return http_response_bad_request('fedTerm/IdP SOAP: Bad SOAP message')

    request_type = lasso.getRequestTypeFromSoapMsg(soap_message)
    if request_type != lasso.REQUEST_TYPE_NAME_ID_MANAGEMENT:
        return http_response_bad_request('fedTerm/IdP SOAP: \
            SOAP message is not a slo message')

    server = build_service_provider(request)
    if not server:
        return http_response_forbidden_request('fedTerm/IdP SOAP: \
            Service provider not configured')

    manage = lasso.NameIdManagement(server)
    if not manage:
        return http_response_forbidden_request('fedTerm/IdP SOAP: \
            Unable to create Login object')

    while True:
        try:
            manage.processRequestMsg(soap_message)
            break
        except (lasso.ServerProviderNotFoundError,
                lasso.ProfileUnknownProviderError):
            provider_id = manage.remoteProviderId
            provider_loaded = load_provider(request, provider_id,
                    server=server, sp_or_idp='idp')

            if not provider_loaded:
                message = _('fedTerm/SOAP: provider %r unknown') % provider_id
                return error_page(request, message, logger=logger)
            else:
                continue
        except lasso.Error, error:
            message = 'fedTerm/IdP SOAP: %s' % lasso.strError(error[0])
            return http_response_forbidden_request(message)

    fed = lookup_federation_by_name_identifier(profile=manage)
    load_federation(request, get_entity_id(request, reverse(metadata)), manage, fed.user)
    try:
        manage.validateRequest()
    except lasso.Error, error:
        message = 'fedTerm/IdP SOAP: %s' % lasso.strError(error[0])
        return http_response_forbidden_request(message)

    fed.delete()

    try:
        manage.buildResponseMsg()
    except:
        message = 'fedTerm/IdP SOAP: %s' % lasso.strError(error[0])
        return http_response_forbidden_request(message)

    django_response = HttpResponse()
    django_response.status_code = 200
    django_response.content_type = 'text/xml'
    django_response.content = manage.msgBody
    return django_response


###
 # manageNameId
 # @request
 #
 # Federation termination: request from Redirect IdP initiated
 ###
def manageNameId(request):
    query = get_saml2_query_request(request)
    if not query:
        return http_response_forbidden_request('fedTerm/IdP Redirect: \
            Unable to handle Single Logout by Redirect without request')

    server = build_service_provider(request)
    if not server:
        return http_response_forbidden_request('fedTerm/IdP Redirect: \
            Service provider not configured')

    manage = lasso.NameIdManagement(server)
    if not manage:
        return http_response_forbidden_request('fedTerm/IdP Redirect: \
            Unable to create Login object')

    try:
        manage.processRequestMsg(query)
    except lasso.Error, error:
        message = 'fedTerm/IdP Redirect: %s' % lasso.strError(error[0])
        return http_response_forbidden_request(message)

    fed = lookup_federation_by_name_identifier(profile=manage)
    load_federation(request, get_entity_id(request, reverse(metadata)), manage, fed.user)
    try:
        manage.validateRequest()
    except lasso.Error, error:
        logger.warning('fedTerm/IdP Redirect: Unable to validate request')
        return

    fed.delete()

    try:
        manage.buildResponseMsg()
    except:
        message = 'fedTerm/IdP Redirect: %s' % lasso.strError(error[0])
        return http_response_forbidden_request(message)

    return HttpResponseRedirect(manage.msgUrl)


#############################################
# Helper functions
#############################################

def get_provider_id_and_options(provider_id):
    if not provider_id:
        provider_id = reverse(metadata)
    options = metadata_options
    if getattr(settings, 'AUTHSAML2_METADATA_OPTIONS', None):
        options.update(settings.AUTHSAML2_METADATA_OPTIONS)
    return provider_id, options


def get_metadata(request, provider_id=None):
    provider_id, options = get_provider_id_and_options(provider_id)
    return get_saml2_metadata(request, provider_id, sp_map=metadata_map,
            options=options)


def create_server(request, provider_id=None):
    provider_id, options = get_provider_id_and_options(provider_id)
    return create_saml2_server(request, provider_id, sp_map=metadata_map,
            options=options)


def http_response_bad_request(message):
    logger.error(message)
    return HttpResponseBadRequest(_(message))


def http_response_forbidden_request(message):
    logger.error(message)
    return HttpResponseForbidden(_(message))


def build_service_provider(request):
    return create_server(request, reverse(metadata))


def setAuthnrequestOptions(provider, login, force_authn, is_passive):
    if not provider or not login:
        return None

    p = get_idp_options_policy(provider)
    if not p:
        return None

    if p.no_nameid_policy:
        login.request.nameIDPolicy = None
    else:
        login.request.nameIDPolicy.format = \
            NAME_ID_FORMATS[p.requested_name_id_format]['samlv2']
        login.request.nameIDPolicy.allowCreate = p.allow_create
        login.request.nameIDPolicy.spNameQualifier = None

    if p.enable_binding_for_sso_response:
        login.request.protocolBinding = p.binding_for_sso_response

    if force_authn is None:
        force_authn = p.want_force_authn_request
    login.request.forceAuthn = force_authn

    if is_passive is None:
        is_passive = p.want_is_passive_authn_request
    login.request.isPassive = is_passive

    return p


def view_profile(request, next='', template_name='profile.html'):
    if 'next' in request.session:
        next = request.session['next']
    else:
        next = next
    if request.user is None \
        or not request.user.is_authenticated() \
        or not hasattr(request.user, '_meta'):
        return HttpResponseRedirect(next)

    logger.info('view_profile: View profile of user %s' % str(request.user))

    #Add creation date
    federations = LibertyProvider.objects \
            .filter(identity_provider__libertyfederation__user=request.user) \
            .values_list('name', flat=True)

    from frontend import AuthSAML2Frontend
    form = AuthSAML2Frontend().form()()
    if not form.fields['provider_id'].choices:
        form = None
    context = {'submit_name': 'submit-%s' % AuthSAML2Frontend().id(),
                REDIRECT_FIELD_NAME: '/profile',
                'form': form}

    return render_to_string(template_name,
            {'next': next,
            'federations': federations,
            'base': '/authsaml2'},
            RequestContext(request, context))


@login_required
@csrf_exempt
def delete_federation(request, next_url='/'):
    next = request.REQUEST.get('next', next_url)
    logger.info('delete_federation: federation deletion requested')
    if request.method == "POST":
        provider_name = request.POST.get('fed')
        if provider_name:
            LibertyFederation.objects.filter(
                    user=request.user,
                    idp__liberty_provider__name=provider_name).update(user=None)
            logger.info('delete_federation: federation %s deleted',
                    provider_name)
            messages.add_message(request, messages.INFO,
                _('Successful federation deletion.'))
            return HttpResponseRedirect(next)
    return HttpResponseRedirect(next)
