import logging
from datetime import timedelta
from xml.etree import ElementTree as ET
from collections import defaultdict

import requests

from django.http import HttpResponseBadRequest, HttpResponse
from django.views.generic.base import View
from django.utils.timezone import now

from authentic2.utils import (get_user_from_session_key, make_url,
        login_require, find_authentication_event, redirect, normalize_attribute_values,
        attribute_values_to_identifier)
from authentic2.attributes_ng.engine import get_attributes
from authentic2.constants import NONCE_FIELD_NAME
from authentic2.views import logout as logout_view

from models import Ticket, Service
from utils import make_id
from constants import (SERVICE_PARAM, RENEW_PARAM, GATEWAY_PARAM,
        TICKET_PARAM, CANCEL_PARAM, SERVICE_TICKET_PREFIX,
        INVALID_REQUEST_ERROR, INVALID_TICKET_SPEC_ERROR,
        INVALID_SERVICE_ERROR, INVALID_TICKET_ERROR,
        CAS10_VALIDATION_FAILURE, CAS20_VALIDATION_FAILURE,
        SERVICE_RESPONSE_ELT, AUTHENTICATION_SUCCESS_ELT, USER_ELT,
        PGT_URL_PARAM, PGT_IOU_PARAM, SESSION_CAS_LOGOUTS,
        CAS10_VALIDATION_SUCCESS, PGT_ELT, PROXIES_ELT, PROXY_ELT,
        PGT_PREFIX, PGT_IOU_PREFIX, PT_PREFIX, TARGET_SERVICE_PARAM,
        BAD_PGT_ERROR, INVALID_TARGET_SERVICE_ERROR, PROXY_UNAUTHORIZED_ERROR,
        PGT_PARAM, PGT_ID_PARAM, CAS20_PROXY_FAILURE, PROXY_SUCCESS_ELT,
        PROXY_TICKET_ELT, INTERNAL_ERROR, CAS_NAMESPACE, ATTRIBUTES_ELT)
from . import app_settings

try:
    ET.register_namespace('cas', 'http://www.yale.edu/tp/cas')
except AttributeError:
    ET._namespace_map['http://www.yale.edu/tp/cas'] = 'cas'


class CasMixin(object):
    '''Common methods'''

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger(__name__)

    def failure(self, request, service, reason):
        self.logger.warning('cas login from %r failed: %s', service, reason)
        if service:
            return redirect(request, service)
        else:
            return HttpResponseBadRequest(content=reason)

    def redirect_to_service(self, request, st):
        if not st.valid():
            return self.failure(request, st.service_url, 'service ticket id is '
                    'not valid')
        else:
            return self.return_ticket(request, st)

    def validate_ticket(self, request, st):
        if not st.service or not request.user.is_authenticated():
            return
        st.user = request.user
        st.validity = True
        st.expire = now() + timedelta(seconds=60)
        st.session_key = request.session.session_key
        st.save()
        if st.service.logout_url:
            request.session.setdefault(SESSION_CAS_LOGOUTS, []).append((
                    st.service.name, 
                    st.service.get_logout_url(request),
                    st.service.logout_use_iframe,
                    st.service.logout_use_iframe_timeout))

    def authenticate(self, request, st):
        '''
           Redirect to an login page, pass a cookie to the login page to
           associate the login event with the service ticket, if renew was
           asked
        '''
        nonce = st.ticket_id
        next_url = make_url('a2-idp-cas-continue', params={
            SERVICE_PARAM: st.service_url, NONCE_FIELD_NAME: nonce})
        return login_require(request, next_url=next_url,
                params={NONCE_FIELD_NAME: nonce})


class LoginView(CasMixin, View):
    http_method_names = ['get']

    def get(self, request):
        service = request.GET.get(SERVICE_PARAM)
        renew = request.GET.get(RENEW_PARAM) is not None
        gateway = request.GET.get(GATEWAY_PARAM) is not None

        if not service:
            return self.failure(request, '', 'no service field')
        model = Service.objects.for_service(service)
        if not model:
            return self.failure(request, service, 'service unknown')
        if renew and gateway:
            return self.failure(request, service, 'renew and gateway cannot be requested '
                    'at the same time')

        st = Ticket()
        st.service = model
        # Limit size of return URL to an acceptable length
        service = service[:4096]
        st.service_url = service
        st.renew = renew
        self.logger.debug('login request from %r renew: %s gateway: %s',
                service, renew, gateway)
        if self.must_authenticate(request, renew, gateway):
            st.save()
            return self.authenticate(request, st)
        self.validate_ticket(request, st)
        if st.valid():
            st.save()
            return redirect(request, service, params={'ticket': st.ticket_id})
        self.logger.debug('gateway requested but no session is open')
        return redirect(request, service)

    def must_authenticate(self, request, renew, gateway):
        '''Does the user needs to authenticate ?
        '''
        return not gateway and (not request.user.is_authenticated() or renew)


class ContinueView(CasMixin, View):
    http_method_names = ['get']

    def get(self, request):
        '''Continue CAS login after authentication'''
        service = request.GET.get(SERVICE_PARAM)
        ticket_id = request.GET.get(NONCE_FIELD_NAME)
        cancel = request.GET.get(CANCEL_PARAM) is not None
        if ticket_id is None:
            return self.failure(request, service, 'missing ticket id')
        if not ticket_id.startswith(SERVICE_TICKET_PREFIX):
            return self.failure(request, service, 'invalid ticket id')
        try:
            st = Ticket.objects.get(ticket_id=ticket_id)
        except Ticket.DoesNotExist:
            return self.failure(request, service, 'unknown ticket id')
        # no valid ticket should be submitted to continue, delete them !
        if st.valid():
            st.delete()
            return self.failure(request, service, 'ticket %r already valid passed to continue' % st.ticket_id)
        # service URL mismatch
        if st.service_url != service:
            st.delete()
            return self.failure(request, service, 'ticket service does not match service parameter')
        # user asked for cancellation
        if cancel:
            st.delete()
            self.logger.debug('login from %s canceled', service)
            return redirect(request, service)
        # Not logged in ? Authenticate again
        if not request.user.is_authenticated():
            return self.authenticate(request, st)
        # Renew requested and ticket is unknown ? Try again
        if st.renew and not find_authentication_event(request, st.ticket_id):
            return self.authenticate(request, st)
        self.validate_ticket(request, st)
        if st.valid():
            return redirect(request, service, params={'ticket': st.ticket_id})
        # Should not happen 
        assert False


class ValidateBaseView(CasMixin, View):
    http_method_names = ['get']
    prefixes = [SERVICE_TICKET_PREFIX]

    def get(self, request):
        try:
            service = request.GET.get(SERVICE_PARAM)
            ticket = request.GET.get(TICKET_PARAM)
            renew = request.GET.get(RENEW_PARAM) is not None
            if service is None:
                return self.failure(request, service, 'service parameter is missing')
            if ticket is None:
                return self.validation_failure(request, service, INVALID_REQUEST_ERROR)
            self.logger.debug('validation service: %r ticket: %r renew: %s', service, ticket, renew)
            if not ticket.split('-')[0] + '-' in self.prefixes:
                return self.validation_failure(request, service, INVALID_TICKET_SPEC_ERROR)
            model = Service.objects.for_service(service)
            if not model:
                return self.validation_failure(request, service, INVALID_SERVICE_ERROR)
            try:
                st = Ticket.objects.get(ticket_id=ticket)
            except Ticket.DoesNotExist:
                st = None
            else:
                st.delete()

            if st is None:
                return self.validation_failure(request, service, INVALID_TICKET_ERROR)
            if service != st.service_url:
                return self.validation_failure(request, service, INVALID_SERVICE_ERROR)
            if not st.valid() or renew and not st.renew:
                return self.validation_failure(request, service, INVALID_TICKET_SPEC_ERROR)
            attributes = self.get_attributes(request, st)
            if st.service.identifier_attribute not in attributes:
                self.logger.error('unable to compute an identifier for user %r and service %s',
                        unicode(st.user), st.service_url)
                return self.validation_failure(request, service, INTERNAL_ERROR)
            # Compute user identifier
            identifier = attribute_values_to_identifier(
                    attributes[st.service.identifier_attribute])
            return self.validation_success(request, st, identifier)
        except:
            raise
            self.logger.exception('internal server error')
            return self.validation_failure(request, service, INTERNAL_ERROR)

    def get_attributes(self, request, st):
        '''Retrieve attribute for users of the session linked to the ticket'''
        if not hasattr(st, 'attributes'):
            wanted_attributes = st.service.get_wanted_attributes()
            user = get_user_from_session_key(st.session_key)
            assert user.pk # not an annymous user
            assert st.user_id == user.pk # session user matches ticket user
            st.attributes = get_attributes({
                'request': request,
                'user': user,
                'service': st.service,
                '__wanted_attributes': wanted_attributes,
            })
        return st.attributes

    def validation_failure(self, request, service, code):
        self.logger.warning('validation failed service: %r code: %s', service, code)
        return self.real_validation_failure(request, service, code)

    def validation_success(self, request, st, identifier):
        self.logger.info('validation success service: %r ticket: %s '
                'user: %r identifier: %r', st.service_url, st.ticket_id, unicode(st.user), identifier)
        return self.real_validation_success(request, st, identifier)


class ValidateView(ValidateBaseView):
    def real_validation_failure(self, request, service, code):
        return HttpResponse(CAS10_VALIDATION_FAILURE,
                content_type='text/plain')

    def real_validation_success(self, request, st, identifier):
        return HttpResponse(CAS10_VALIDATION_SUCCESS % identifier,
                content_type='text/plain')


class ServiceValidateView(ValidateBaseView):
    add_proxies = False

    def real_validation_failure(self, request, service, code, message=''):
        message = message or self.get_cas20_error_message(code)
        return HttpResponse(CAS20_VALIDATION_FAILURE % (code, message),
                content_type='text/xml')

    def get_cas20_error_message(self, code):
        return '' # FIXME

    def real_validation_success(self, request, st, identifier):
        root = ET.Element(SERVICE_RESPONSE_ELT)
        success = ET.SubElement(root, AUTHENTICATION_SUCCESS_ELT)
        user = ET.SubElement(success, USER_ELT)
        user.text = unicode(identifier)
        self.provision_pgt(request, st, success)
        self.provision_attributes(request, st, success)
        return HttpResponse(ET.tostring(root, encoding='utf-8'),
                content_type='text/xml')

    def provision_attributes(self, request, st, success):
        '''Add attributes to the CAS 2.0 ticket'''
        values = defaultdict(lambda: set())
        ctx = self.get_attributes(request, st)
        for attribute in st.service.attribute_set.all():
            if not attribute.enabled:
                continue
            slug = attribute.slug
            name = attribute.attribute_name
            if name in ctx:
                normalized = normalize_attribute_values(ctx[name])
                values[slug].update(normalized)
        if values:
            attributes_elt = ET.SubElement(success, ATTRIBUTES_ELT)
        for key, values in values.iteritems():
            for value in values:
                attribute_elt = ET.SubElement(attributes_elt, '{%s}%s' % (CAS_NAMESPACE, key))
                attribute_elt.text = unicode(value)


    def provision_pgt(self, request, st, success):
        '''Provision a PGT ticket if requested
        '''
        pgt_url = request.GET.get(PGT_URL_PARAM)
        if not pgt_url:
            return
        if not pgt_url.startswith('https://'):
            self.logger.warning('ignoring non HTTP pgtUrl %r', pgt_url)
            return
        # PGT URL must be declared
        if not st.service.match_service(pgt_url):
            self.logger.warning('pgtUrl %r does not match service %r',
                pgt_url, st.service.slug)
        pgt = make_id(PGT_PREFIX)
        pgt_iou = make_id(PGT_IOU_PREFIX)
        # Skip PGT_URL check for testing purpose
        # instead store PGT_IOU / PGT association in session
        if app_settings.CHECK_PGT_URL:
            response = requests.get(pgt_url, params={
               PGT_ID_PARAM: pgt,
               PGT_IOU_PARAM: pgt_iou})
            if response.status_code != 200:
                self.logger.warning('pgtUrl %r returned non 200 code: %d',
                    pgt_url, response.status_code)
                return
        else:
            request.session[pgt_iou] = pgt
        proxies = ('%s %s' % (pgt_url, st.proxies)).strip()
        # Save the PGT ticket
        Ticket.objects.create(
                ticket_id=pgt,
                expire=None,
                service=st.service,
                service_url=st.service_url,
                validity=True,
                user=st.user,
                session_key=st.session_key,
                proxies=proxies)
        user = ET.SubElement(success, PGT_ELT)
        user.text = pgt_iou
        if self.add_proxies:
            proxies_elt = ET.SubElement(success, PROXIES_ELT)
            for proxy in st.proxies.split():
                proxy_elt = ET.SubElement(proxies_elt, PROXY_ELT)
                proxy_elt.text = proxy


class ProxyView(View):
    http_method_names = ['get']
    
    def get(self, request):
        pgt = request.GET.get(PGT_PARAM)
        target_service_url = request.GET.get(TARGET_SERVICE_PARAM)
        if not pgt or not target_service_url:
            return self.validation_failure(INVALID_REQUEST_ERROR,
                    "'pgt' and 'targetService' parameters are both required")
        if not pgt.startswith(PGT_PREFIX):
            return self.validation_failure(BAD_PGT_ERROR,
                    'a proxy granting ticket must start with PGT-')
        try:
            pgt = Ticket.objects.get(ticket_id=pgt)
        except Ticket.DoesNotExist:
            pgt = None
        if pgt is None:
            return self.validation_failure(BAD_PGT_ERROR, 'pgt does not '
                    'exist')
        if not pgt.valid():
            pgt.delete()
            return self.validation_failure(BAD_PGT_ERROR, 'session has expired')
        target_service = Service.objects.for_service(target_service_url)
        # No target service exists for this url, maybe the URL is missing from
        # the urls field
        if not target_service:
            return self.validation_failure(INVALID_TARGET_SERVICE_ERROR,
                    'target service is invalid')
        # Verify that the requested service is authorized to get proxy tickets
        # for the target service
        if not target_service.proxy.filter(pk=pgt.service_id).exists():
            return self.validation_failure(PROXY_UNAUTHORIZED_ERROR,
                    'proxying to the target service is forbidden')
        pt = Ticket.objects.create(
            ticket_id=make_id(PT_PREFIX),
            validity=True,
            expire=now()+timedelta(seconds=60),
            service=target_service,
            service_url=target_service_url,
            user=pgt.user,
            session_key=pgt.session_key,
            proxies=pgt.proxies)
        return self.validation_success(request, pt)

    def validation_failure(self, code, reason):
        return HttpResponse(CAS20_PROXY_FAILURE % (code, reason),
                content_type='text/xml')

    def validation_success(self, request, pt):
        root = ET.Element(SERVICE_RESPONSE_ELT)
        success = ET.SubElement(root, PROXY_SUCCESS_ELT)
        proxy_ticket = ET.SubElement(success, PROXY_TICKET_ELT)
        proxy_ticket.text = pt.ticket_id
        return HttpResponse(ET.tostring(root, encoding='utf-8'),
                content_type='text/xml')


class ProxyValidateView(ServiceValidateView):
    http_method_names = ['get']
    prefixes = [SERVICE_TICKET_PREFIX, PT_PREFIX]
    add_proxies = True


class LogoutView(View):
    http_method_names = ['get']

    def get(self, request):
        referrer = request.META['HTTP_REFERER']
        next_url = request.REQUEST.get('service') or make_url('auth_homepage')
        if referrer:
            model = Service.objects.for_service(referrer)
            if model:
                return logout_view(request, next_url=next_url,
                        check_referer=False, do_local=False)
        return redirect(request, next_url)

login = LoginView.as_view()
logout = LogoutView.as_view()
_continue = ContinueView.as_view()
validate = ValidateView.as_view()
service_validate = ServiceValidateView.as_view()
proxy = ProxyView.as_view()
proxy_validate = ProxyValidateView.as_view()
