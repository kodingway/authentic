import logging
import random
import datetime
import string
from xml.etree import ElementTree as ET

from django.http import HttpResponseRedirect, HttpResponseBadRequest, \
    HttpResponse, HttpResponseNotAllowed
from django.core.urlresolvers import reverse
from django.contrib.auth.views import redirect_to_login, logout
from django.utils.http import urlquote, urlencode
from django.conf.urls.defaults import patterns, url
from django.conf import settings

from models import CasTicket
from authentic2.auth2_auth.views import redirect_to_login as \
    auth2_redirect_to_login
import authentic2.auth2_auth.models as auth2_auth_models
from constants import SERVICE_PARAM, RENEW_PARAM, GATEWAY_PARAM, ID_PARAM, \
    CANCEL_PARAM, SERVICE_TICKET_PREFIX, TICKET_PARAM, \
    CAS10_VALIDATION_FAILURE, CAS10_VALIDATION_SUCCESS, PGT_URL_PARAM, \
    INVALID_REQUEST_ERROR, INVALID_TICKET_ERROR, INVALID_SERVICE_ERROR, \
    INTERNAL_ERROR, CAS20_VALIDATION_FAILURE, CAS20_VALIDATION_SUCCESS, \
    CAS_NAMESPACE, USER_ELT, SERVICE_RESPONSE_ELT, AUTHENTICATION_SUCCESS_ELT

logger = logging.getLogger('authentic2.idp.idp_cas')

ALPHABET = string.letters+string.digits+'-'

SAML_RESPONSE_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header/>
<SOAP-ENV:Body>
<Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" IssueInstant="2013-05-16T16:07:35Z" MajorVersion="1" MinorVersion="1" Recipient="https://amonecole.monreseau.lan/webcalendar/login.php" ResponseID="{reponse_id}">
  <Status>
    <StatusCode Value="samlp:Success">
    </StatusCode>
  </Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="{assertion_id}" IssueInstant="{issue_instant}" Issuer="{issuer}" MajorVersion="1" MinorVersion="1">
<Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
      <AudienceRestrictionCondition>
        <Audience>{audience}</Audience>
      </AudienceRestrictionCondition>
    </Conditions>
    <AttributeStatement>
      <Subject>
        <NameIdentifier>{name_id}</NameIdentifier>
        <SubjectConfirmation>
          <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:artifact</ConfirmationMethod>
        </SubjectConfirmation>
      </Subject>
      {attributes}

    </AttributeStatement>
    <AuthenticationStatement AuthenticationInstant="{authentication_instant}" AuthenticationMethod="{authentication_method}">
      <Subject>
        <NameIdentifier>{name_id}</NameIdentifier>
        <SubjectConfirmation>
          <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:artifact</ConfirmationMethod>
        </SubjectConfirmation>
      </Subject>
    </AuthenticationStatement>
  </Assertion>
</Response>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''

class CasProvider(object):
    def get_url(self):
        return patterns('cas',
                url('^login$', self.login),
                url('^continue$', self.continue_cas),
                url('^validate$', self.validate),
                url('^serviceValidate$', self.service_validate),
                url('^samlValidate$', self.saml_validate),
                url('^logout$', self.logout))
    url = property(get_url)

    def make_id(self, prefix='', length=29):
        l = length-len(prefix)
        content = ( random.SystemRandom().choice(ALPHABET) for x in range(l) )
        return prefix + ''.join(content)

    def create_service_ticket(self, service, renew=False, validity=True,
            expire=None, user=None):
        '''Create a fresh service ticket'''
        validity = validity and not renew
        return CasTicket.objects.create(ticket_id=self.make_id(prefix='ST-'),
            service=service,
            renew=renew,
            validity=validity,
            expire=None,
            user=user)

    def check_authentication(self, request, st):
        '''
           Check that the given service ticket is linked to an authentication
           event.
        '''
        return False

    def failure(self, request, reason):
        '''
           Return a HTTP 400 code with the @reason argument as content.
        '''
        return HttpResponseBadRequest(content=reason)

    def login(self, request):
        if request.method != 'GET':
            return HttpResponseBadRequest('Only GET HTTP verb is accepted')
        service = request.GET.get(SERVICE_PARAM)
        renew = request.GET.get(RENEW_PARAM) is not None
        gateway = request.GET.get(GATEWAY_PARAM) is not None

        if not service:
            return self.failure(request, 'no service field')
        if not service.startswith('http://') and not \
                service.startswith('https://'):
            return self.failure(request, 'service is not an HTTP or HTTPS URL')
        return self.handle_login(request, service, renew, gateway)

    def must_authenticate(self, request, renew):
        '''Does the user needs to authenticate ?

           You can refer to the current request and to the renew parameter from
           the login reuest.

           Returns a boolean.
        '''
        return not request.user.is_authenticated() or renew

    def get_cas_user(self, request):
        '''Return an ascii string representing the user.

           It should usually be the uid from an user record in a LDAP
        '''
        return request.user.username

    def handle_login(self, request, service, renew, gateway, duration=None):
        '''
           Handle a login request

           @service: URL where the CAS ticket will be returned
           @renew: whether to re-authenticate the user
           @gateway: do not let the IdP interact with the user

           It is an extension point
        '''
        logger.debug('Handling CAS login for service:%r with parameters \
renew:%s and gateway:%s' % (service, renew, gateway))

        if duration is None or duration < 0:
            duration = 5*60
        if duration:
            expire = datetime.datetime.now() + \
                datetime.timedelta(seconds=duration)
        else:
            expire = None
        if self.must_authenticate(request, renew):
            st = self.create_service_ticket(service, validity=False,
                    renew=renew, expire=expire)
            return self.authenticate(request, st, passive=gateway)
        else:
            st = self.create_service_ticket(service, expire=expire,
                    user=self.get_cas_user(request))
            return self.handle_login_after_authentication(request, st)

    def cas_failure(self, request, st, reason):
        logger.debug('%s, redirecting without ticket to %r' % (reason, \
            st.service))
        st.delete()
        return HttpResponseRedirect(st.service)

    def authenticate(self, request, st, passive=False):
        '''
           Redirect to an login page, pass a cookie to the login page to
           associate the login event with the service ticket, if renew was
           asked

           It is an extension point. If your application support some passive
           authentication, it must be tried here instead of failing.
           @request: current django request
           @st: a currently invalid service ticket
           @passive: whether we can interact with the user
        '''

        if passive:
            return self.cas_failure(request, st,
                    'user needs to log in and gateway is True')
        if st.renew:
            raise NotImplementedError('renew is not implemented')
        return redirect_to_login(next='%s?id=%s' % (reverse(self.continue_cas),
                urlquote(st.ticket_id)))

    def continue_cas(self, request):
        '''Continue CAS login after authentication'''
        ticket_id = request.GET.get(ID_PARAM)
        cancel = request.GET.get(CANCEL_PARAM) is not None
        if ticket_id is None:
            return self.failure(request, 'missing ticket id')
        if not ticket_id.startswith(SERVICE_TICKET_PREFIX):
            return self.failure(request, 'invalid ticket id')
        try:
            st = CasTicket.objects.get(ticket_id=ticket_id)
        except CasTicket.DoesNotExist:
            return self.failure(request, 'unknown ticket id')
        if cancel:
            return self.cas_failure(request, st, 'login cancelled')
        if st.renew:
            # renew login
            if self.check_authentication(request, st):
                return self.handle_login_after_authentication(request, st)
            else:
                return self.authenticate(request, st)
        elif self.must_authenticate(request, False):
            # not logged ? Yeah do it again!
            return self.authenticate(request, st)
        else:
            # normal login
            st.user = self.get_cas_user(request)
            st.validity = True
            st.save()
        return self.handle_login_after_authentication(request, st)

    def handle_login_after_authentication(self, request, st):
        if not st.valid():
            return self.cas_failure(request, st,
                    'service ticket id is not valid')
        else:
            return self.return_ticket(request, st)

    def return_ticket(self, request, st):
        return HttpResponseRedirect('%s?ticket=%s' % (st.service,
            st.ticket_id))

    def validate(self, request):
        if request.method != 'GET':
            return self.failure(request, 'Only GET HTTP verb is accepted')
        service = request.GET.get(SERVICE_PARAM)
        ticket = request.GET.get(TICKET_PARAM)
        renew = request.GET.get(RENEW_PARAM) is not None
        if service is None:
            return self.failure(request, 'service parameter is missing')
        if service is None:
            return self.failure(request, 'ticket parameter is missing')
        if not ticket.startswith(SERVICE_TICKET_PREFIX):
            return self.failure(request, 'invalid ticket prefix')
        try:
            st = CasTicket.objects.get(ticket_id=ticket)
            st.delete()
        except CasTicket.DoesNotExist:
            st = None
        if st is None \
                or not st.valid() \
                or (st.renew ^ renew) \
                or st.service != service:
            return HttpResponse(CAS10_VALIDATION_FAILURE)
        else:
            return HttpResponse(CAS10_VALIDATION_SUCCESS % st.user)

    def get_cas20_error_message(self, code):
        return '' # FIXME

    def cas20_error(self, request, code):
        message = self.get_cas20_error_message(code)
        return HttpResponse(CAS20_VALIDATION_FAILURE % (code, message),
                content_type='text/xml')

    def get_attributes(self, request, st):
        # XXX: st.service contains the requesting service URL, use it to match CAS attribute policy
        return {}, False

    def saml_build_attributes(self, request, st):
        attributes, section = self.get_attributes(request, st)
        result = []
        for key, value in attributes.iteritems():
            key = key.encode('utf-8')
            value = value.encode('utf-8')
            result.append('''<Attribute AttributeName="{key}" AttributeNamespace="http://www.ja-sig.org/products/cas/">
<AttributeValue>{value}</AttributeValue>
</Attribute>'''.format(key=key, value=value))
        return ''.join(result)

    def saml_validate(self, request):
        if request.method != 'POST':
            return HttpResponseNotAllowed(['POST'])
        root = ET.fromstring(request.body)
        ns = dict(
            SOAP_ENV = 'http://schemas.xmlsoap.org/soap/envelope/',
            samlp = 'urn:oasis:names:tc:SAML:1.0:protocol')
        if root.tag != '{%(SOAP_ENV)s}Envelope' % ns:
            return self.saml_error(request, INVALID_REQUEST_ERROR)
        assertion_artifact = root.find('{%(SOAP_ENV)s}Body/{%(samlp)s}Request/{%(samlp)s}AssertionArtifact')
        ticket = assertion_artifact.text
        try:
            st = CasTicket.objects.get(ticket_id=ticket)
            st.delete()
        except CasTicket.DoesNotExist:
            st = None
        if st is None or not st.valid():
            return self.saml_error(request, INVALID_TICKET_ERROR)
        new_id = self.generate_id()

        ctx = {
                'response_id': new_id,
                'assertion_id': new_id,
                'issue_instant': '', # XXX: iso time
                'issuer': request.build_absolute_uri('/'),
                'not_before': '', # XXX: issue time - lag
                'not_on_or_after': '', # XXX issue time + lag,
                'audience': st.service.encode('utf-8'),
                'name_id': request.user.username,
                'attributes': self.saml_build_attributes(request, st),
        }
        return HttpResponse(SAML_RESPONSE_TEMPLATE.format(**ctx),
                content_type='text/xml')

    def service_validate_success_response(self, request, st):
        attributes, section = self.get_attributes(request, st)
        root = ET.Element('{%s}%s' % (CAS_NAMESPACE, SERVICE_RESPONSE_ELT))
        success = ET.SubElement(root, '{%s}%s' % (CAS_NAMESPACE, AUTHENTICATION_SUCCESS_ELT))
        if attributes:
            if section == 'default':
                user = success
            else:
                user = ET.SubElement(success, '{%s}%s' % (CAS_NAMESPACE, section))
            for key, value in attributes.iteritems():
                elt = ET.SubElement(user, '{%s}%s' % (CAS_NAMESPACE, key))
                elt.text = unicode(value)
        else:
            user = ET.SubElement(success, '{%s}%s' % (CAS_NAMESPACE, USER_ELT))
            user.text = unicode(st.user)
        return HttpResponse(ET.tostring(root, encoding='utf8'),
                content_type='text/xml')

    def service_validate(self, request):
        '''
           CAS 2.0 serviceValidate endpoint.
        '''
        try:
            if request.method != 'GET':
                return self.failure('Only GET HTTP verb is accepted')
            service = request.GET.get(SERVICE_PARAM)
            ticket = request.GET.get(TICKET_PARAM)
            renew = request.GET.get(RENEW_PARAM) is not None
            pgt_url = request.GET.get(PGT_URL_PARAM)
            if service is None:
                return self.cas20_error(request, INVALID_REQUEST_ERROR)
            if service is None:
                return self.cas20_error(request, INVALID_REQUEST_ERROR)
            if not ticket.startswith(SERVICE_TICKET_PREFIX):
                return self.cas20_error(request, INVALID_TICKET_ERROR)
            try:
                st = CasTicket.objects.get(ticket_id=ticket)
                st.delete()
            except CasTicket.DoesNotExist:
                st = None
            if st is None \
                    or not st.valid() \
                    or (st.renew ^ renew):
                return self.cas20_error(request, INVALID_TICKET_ERROR)
            if st.service != service:
                return self.cas20_error(request, INVALID_SERVICE_ERROR)
            if pgt_url:
                raise NotImplementedError(
                        'CAS 2.0 pgtUrl parameter is not handled')
            return self.service_validate_success_response(request, st)
        except Exception:
            logger.exception('error in cas:service_validate')
            return self.cas20_error(INTERNAL_ERROR)

    def logout(self, request):
        next = request.GET.get('url')
        return logout(request, next_page=next)

class Authentic2CasProvider(CasProvider):
    def authenticate(self, request, st, passive=False):
        next = '%s?id=%s' % (reverse(self.continue_cas),
                urlquote(st.ticket_id))
        if passive:
            if getattr(settings, 'AUTH_SSL', False):
                query = { 'next': next,
                    'nonce': st.ticket_id }
                return HttpResponseRedirect('%s?%s' %
                        (reverse('user_signin_ssl'), urlencode(query)))
            else:
                return self.cas_failure(request, st, 
                    '''user needs to login and no passive authentication \
is possible''')
        return auth2_redirect_to_login(request, next=next, nonce=st.ticket_id)

    def check_authentication(self, request, st):
        try:
            ae = auth2_auth_models.AuthenticationEvent.objects \
                    .get(nonce=st.ticket_id)
            st.user = ae.who
            st.validity = True
            st.save()
            return True
        except auth2_auth_models.AuthenticationEvent.DoesNotExist:
            return False
