"""
    Discovery Service Responder
    See Identity Provider Discovery Service Protocol and Profile
    OASIS Committee Specification 01
    27 March 2008
"""


import logging
import urlparse
import urllib

from xml.dom.minidom import parseString

from django.http import HttpResponseRedirect
from django.conf.urls import patterns
from django.utils.translation import ugettext as _
from django.core.urlresolvers import reverse
from django.utils.http import urlquote

from authentic2 import settings
from authentic2.saml.common import error_page
from authentic2.saml.models import LibertyProvider

logger = logging.getLogger('authentic2.disco.responder')


USE_OF_METADATA = False
try:
    USE_OF_METADATA = settings.DISCO_USE_OF_METADATA
except:
    logger.error("disco: missing parameters in settings for idp discovery.")


def save_key_values(request, *values):
    request.session['save_key_values'] = values


def get_and_delete_key_values(request):
    if 'save_key_values' in request.session:
        return request.session['save_key_values']
    return None


def set_or_refresh_prefered_idp(request, prefered_idp):
    # XXX: Set cookie with the prefered idp entity ID
    request.session['prefered_idp'] = prefered_idp


def get_prefered_idp(request):
    # XXX: Read cookie if any
    if 'prefered_idp' in request.session:
        request.session['prefered_idp']
    return None


def is_known_idp(idp):
    # XXX: Check that the IdP selected is in the list of known idp
    return True


def get_disco_return_url_from_metadata(entity_id):
    liberty_provider = None
    try:
        liberty_provider = LibertyProvider.objects.get(entity_id=entity_id)
        liberty_provider.service_provider
    except:
        logger.warn("get_disco_return_url_from_metadata: "
            "unknown service provider %s" \
                % entity_id)
        return None
    dom = parseString(liberty_provider.metadata.encode('utf8'))
    endpoints = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol', 'DiscoveryResponse')
    if not endpoints:
        logger.warn("get_disco_return_url_from_metadata: "
            "no discovery service endpoint for %s" \
                % entity_id)
        return None
    ep = None
    value = 0
    first = True
    # An endpoint is of type IndexedEndpointType
    # Ignore malformed endpoint with no index
    for endpoint in endpoints:
        if 'index' in endpoint.attributes.keys():
            if first:
                ep = endpoint
                value = int(endpoint.attributes['index'].value)
                first = False
            if int(endpoint.attributes['index'].value) < value:
                value = int(endpoint.attributes['index'].value)
                ep = endpoint
    if not ep:
        logger.warn("get_disco_return_url_from_metadata: "
            "no valid endpoint for %s" \
                % entity_id)
        return None

    logger.debug("get_disco_return_url_from_metadata: "
        "found endpoint with index %s" \
            % str(value))
    if 'Location' in ep.attributes.keys():
        location = ep.attributes['Location'].value
        logger.debug("get_disco_return_url_from_metadata: "
            "location is %s" \
                % location)
        return location

    logger.warn("get_disco_return_url_from_metadata: "
        "no location found for endpoint with index %s" \
            % str(value))
    return None


def is_param_id_in_return_url(return_url, returnIDParam):
    url = urlparse.urlparse(return_url)
    if url.query and returnIDParam in urlparse.parse_qs(url.query):
        return True
    return False


def add_param_to_url(url, param_name, value):
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    if query:
        qs = urlparse.parse_qs(query)
        qs[param_name] = [value]
        query = urllib.urlencode(qs)
    else:
        query = '%s=%s' % (param_name, value)
    return urlparse.urlunparse((scheme, netloc, path, params, query, fragment))


def disco(request):
    if not request.method == "GET":
        message = _('disco: HTTP request not supported %s' % request.method)
        return error_page(request, message, logger=logger)

    entityID = None
    _return = None
    policy = \
        "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single",
    returnIDParam = None
    isPassive = False

    # Back from the selection interface?
    idp_selected = request.GET.get('idp_selected', '')

    # Back from the selection interface
    if idp_selected:
        logger.info("disco: "
            "back from the idp selection interface with value %s" \
                % idp_selected)

        if not is_known_idp(idp_selected):
            message = 'The idp is unknown.'
            logger.warn("disco: Unknown selected idp %s" % idp_selected)
            save_key_values(request, entityID, _return, policy, returnIDParam, isPassive)
            return HttpResponseRedirect(reverse(idp_selection))

        entityID, _return, policy, returnIDParam, isPassive = get_and_delete_key_values(request)

    # Not back from the selection interface
    else:

        # Discovery request parameters
        entityID = request.GET.get('entityID', '')
        _return = request.GET.get('return', '')
        policy = request.GET.get('idp_selected',
    'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single')
        returnIDParam = request.GET.get('returnIDParam', 'entityID')
        isPassive = request.GET.get('isPassive', '')
        if isPassive and isPassive == 'true':
            isPassive=True
        else:
            isPAssive=False

    if not entityID:
        message = _('disco: missing mandatory parameter entityID')
        return error_page(request, message, logger=logger)

    if not policy == \
'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single':
        message = _('disco: policy not implemented')
        return error_page(request, message, logger=logger)

    # If we use metadata, we ignore the parameter return and take it from the
    # md. Else and if no return parameter in query, it is an unconformant SP.
    return_url = None
    if USE_OF_METADATA:
        return_url = get_disco_return_url_from_metadata(entityID)
    else:
        return_url = _return
    if not return_url:
        message = _('disco: unable to find a valid return url for %s' \
            % entityID)
        return error_page(request, message, logger=logger)

    # Check that the return_url does not already contain a param with name
    # equal to returnIDParam. Else, it is an unconformant SP.
    if is_param_id_in_return_url(return_url, returnIDParam):
        message = _('disco: invalid return url %s for %s' \
            % (return_url, entityID))
        return error_page(request, message, logger=logger)

    # not back from selection interface
    if not idp_selected:
        idp_selected = get_prefered_idp(request)

    # not back from selection interface and no registered prefered idp
    if not idp_selected:
        # no idp selected and we must not interect with the user
        if isPassive:
            #No IdP selected = just return to the return url
            return HttpResponseRedirect(return_url)
        # Go to selection interface
        else:
            save_key_values(request, entityID, _return, policy, returnIDParam,
                isPassive)
            return HttpResponseRedirect(reverse(idp_selection))

    # We got it!
    set_or_refresh_prefered_idp(request, idp_selected)
    return HttpResponseRedirect(add_param_to_url(return_url, returnIDParam,
        idp_selected))

def idp_selection(request):
    # XXX: Code here the IdP selection
    idp_selected = urlquote('http://www.identity-hub.com/idp/saml2/metadata')
    return HttpResponseRedirect('%s?idp_selected=%s' \
        % (reverse(disco), idp_selected))

urlpatterns = patterns('',
    (r'^disco$', disco),
    (r'^idp_selection$', idp_selection),
)
