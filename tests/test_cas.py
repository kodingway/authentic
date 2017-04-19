import urlparse


from django.test.client import RequestFactory, Client
from django.test.utils import override_settings


from authentic2.compat import get_user_model
from authentic2_idp_cas.models import Ticket, Service, Attribute
from authentic2_idp_cas import constants
from authentic2.constants import AUTHENTICATION_EVENTS_SESSION_KEY, NONCE_FIELD_NAME
from authentic2.a2_rbac.utils import get_default_ou
from django_rbac.utils import get_role_model

from utils import Authentic2TestCase

CAS_NAMESPACES = {
    'cas': constants.CAS_NAMESPACE,
}


@override_settings(A2_IDP_CAS_ENABLE=True)
class CasTests(Authentic2TestCase):
    LOGIN = 'test'
    PASSWORD = 'test'
    EMAIL = 'test@example.com'
    FIRST_NAME = 'John'
    LAST_NAME = 'Doe'
    NAME = 'CAS service'
    SLUG = 'cas-service'
    URL = 'https://casclient.com/'
    NAME2 = 'CAS service2'
    SLUG2 = 'cas-service2'
    URL2 = 'https://casclient2.com/ https://other.com/'
    SERVICE2_URL = 'https://casclient2.com/service/'
    PGT_URL = 'https://casclient.con/pgt/'


    def setUp(self):
        User = get_user_model()
        Role = get_role_model()
        self.user = User.objects.create_user(self.LOGIN,
                password=self.PASSWORD, email=self.EMAIL,
                first_name=self.FIRST_NAME, last_name=self.LAST_NAME)
        self.service = Service.objects.create(name=self.NAME, slug=self.SLUG,
                urls=self.URL, identifier_attribute='django_user_username',
                ou=get_default_ou(), logout_url=self.URL + 'logout/')
        self.service_attribute1 = Attribute.objects.create(
                service=self.service,
                slug='email',
                attribute_name='django_user_email')
        self.service2 = Service.objects.create(name=self.NAME2,
                slug=self.SLUG2, urls=self.URL2,
                ou=get_default_ou(), identifier_attribute='django_user_email')
        self.service2_attribute1 = Attribute.objects.create(
                service=self.service2,
                slug='username',
                attribute_name='django_user_username')
        self.authorized_service = Role.objects.create(name='rogue', ou=get_default_ou())
        self.factory = RequestFactory()

    def test_service_matching(self):
        self.service.clean()
        self.service2.clean()
        self.assertEqual(Service.objects.for_service(self.URL), self.service)
        for service in self.URL2.split():
            self.assertEqual(Service.objects.for_service(service), self.service2)
        self.assertEqual(Service.objects.for_service('http://google.com'), None)

    def test_login_failure(self):
        client = Client()
        response = client.get('/idp/cas/login')
        self.assertEqual(response.status_code, 400)
        self.assertIn('no service', response.content)
        response = client.get('/idp/cas/login', {constants.SERVICE_PARAM: 'http://google.com/'})
        self.assertRedirectsComplex(response, 'http://google.com/')
        response = client.get('/idp/cas/login', {constants.SERVICE_PARAM: self.URL,
            constants.RENEW_PARAM: '', constants.GATEWAY_PARAM: ''})
        self.assertRedirectsComplex(response, self.URL)
        response = client.get('/idp/cas/login', {constants.SERVICE_PARAM: self.URL,
            constants.GATEWAY_PARAM: ''})
        self.assertRedirectsComplex(response, self.URL)

    def test_role_access_control_denied(self):
        client = Client()
        service = self.service
        service.add_authorized_role(self.authorized_service)
        service.unauthorized_url = 'https://casclient.com/loser/'
        service.save()
        assert service.authorized_roles.exists() is True
        response = client.get('/idp/cas/login', {constants.SERVICE_PARAM: self.URL})
        location = response['Location']
        query = urlparse.parse_qs(location.split('?')[1])
        next_url, next_url_query = query['next'][0].split('?')
        next_url_query = urlparse.parse_qs(next_url_query)
        response = client.post(location, {'login-password-submit': '',
                               'username': self.LOGIN, 'password': self.PASSWORD}, follow=False)
        response = client.get(response.url)
        self.assertIn('https://casclient.com/loser/', response.content)

    def test_role_access_control_granted(self):
        client = Client()
        service = self.service
        service.add_authorized_role(self.authorized_service)
        get_user_model().objects.get(username=self.LOGIN).roles.add(self.authorized_service)
        assert service.authorized_roles.exists() is True
        response = client.get('/idp/cas/login', {constants.SERVICE_PARAM: self.URL})
        location = response['Location']
        query = urlparse.parse_qs(location.split('?')[1])
        next_url, next_url_query = query['next'][0].split('?')
        next_url_query = urlparse.parse_qs(next_url_query)
        response = client.post(location, {'login-password-submit': '',
                               'username': self.LOGIN, 'password': self.PASSWORD}, follow=False)
        response = client.get(response.url)
        client = Client()
        ticket_id = urlparse.parse_qs(response.url.split('?')[1])[constants.TICKET_PARAM][0]
        response = client.get('/idp/cas/validate', {constants.TICKET_PARAM:
                              ticket_id, constants.SERVICE_PARAM: self.URL})

    def test_login_validate(self):
        response = self.client.get('/idp/cas/login', {constants.SERVICE_PARAM: self.URL})
        self.assertEquals(response.status_code, 302)
        ticket = Ticket.objects.get()
        location = response['Location']
        url = location.split('?')[0]
        query = urlparse.parse_qs(location.split('?')[1])
        self.assertEquals(url, 'http://testserver/login/')
        self.assertIn('nonce', query)
        self.assertIn('next', query)
        self.assertEquals(query['nonce'], [ticket.ticket_id])
        next_url, next_url_query = query['next'][0].split('?')
        next_url_query = urlparse.parse_qs(next_url_query)
        self.assertEquals(next_url, '/idp/cas/continue/')
        self.assertEquals(set(next_url_query.keys()),
                set([constants.SERVICE_PARAM, NONCE_FIELD_NAME]))
        self.assertEquals(next_url_query[constants.SERVICE_PARAM], [self.URL])
        self.assertEquals(next_url_query[NONCE_FIELD_NAME], [ticket.ticket_id])
        response = self.client.post(location, {'login-password-submit': '',
            'username': self.LOGIN, 'password': self.PASSWORD}, follow=False)
        self.assertIn(AUTHENTICATION_EVENTS_SESSION_KEY, self.client.session)
        self.assertIn('nonce', self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0])
        self.assertIn(ticket.ticket_id, self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0]['nonce'])
        self.assertRedirectsComplex(response, query['next'][0], nonce=ticket.ticket_id)
        response = self.client.get(response.url)
        self.assertRedirectsComplex(response, self.URL, ticket=ticket.ticket_id)
        # Check logout state has been updated
        ticket = Ticket.objects.get()
        self.assertIn(constants.SESSION_CAS_LOGOUTS, self.client.session)
        self.assertEquals(self.client.session[constants.SESSION_CAS_LOGOUTS],
                [[ticket.service.name, ticket.service.logout_url, ticket.service.logout_use_iframe,
                    ticket.service.logout_use_iframe_timeout]])
        # Do not the same client for direct calls from the CAS service provider
        # to prevent use of the user session
        client = Client()
        ticket_id = urlparse.parse_qs(response.url.split('?')[1])[constants.TICKET_PARAM][0]
        response = client.get('/idp/cas/validate', {constants.TICKET_PARAM:
            ticket_id, constants.SERVICE_PARAM: self.URL})
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response['content-type'], 'text/plain')
        self.assertEquals(response.content, 'yes\n%s\n' % self.LOGIN)
        # Verify ticket has been deleted
        with self.assertRaises(Ticket.DoesNotExist):
            Ticket.objects.get()

    def test_login_service_validate(self):
        response = self.client.get('/idp/cas/login/', {constants.SERVICE_PARAM: self.URL})
        self.assertEquals(response.status_code, 302)
        ticket = Ticket.objects.get()
        location = response['Location']
        url = location.split('?')[0]
        query = urlparse.parse_qs(location.split('?')[1])
        self.assertEquals(url, 'http://testserver/login/')
        self.assertIn('nonce', query)
        self.assertIn('next', query)
        self.assertEquals(query['nonce'], [ticket.ticket_id])
        next_url, next_url_query = query['next'][0].split('?')
        next_url_query = urlparse.parse_qs(next_url_query)
        self.assertEquals(next_url, '/idp/cas/continue/')
        self.assertEquals(set(next_url_query.keys()),
                set([constants.SERVICE_PARAM, NONCE_FIELD_NAME]))
        self.assertEquals(next_url_query[constants.SERVICE_PARAM], [self.URL])
        self.assertEquals(next_url_query[NONCE_FIELD_NAME], [ticket.ticket_id])
        response = self.client.post(location, {'login-password-submit': '',
            'username': self.LOGIN, 'password': self.PASSWORD}, follow=False)
        self.assertIn(AUTHENTICATION_EVENTS_SESSION_KEY, self.client.session)
        self.assertIn('nonce', self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0])
        self.assertIn(ticket.ticket_id, self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0]['nonce'])
        self.assertRedirectsComplex(response, query['next'][0], nonce=ticket.ticket_id)
        response = self.client.get(response.url)
        self.assertRedirectsComplex(response, self.URL, ticket=ticket.ticket_id)
        # Check logout state has been updated
        ticket = Ticket.objects.get()
        self.assertIn(constants.SESSION_CAS_LOGOUTS, self.client.session)
        self.assertEquals(self.client.session[constants.SESSION_CAS_LOGOUTS],
                [[ticket.service.name, ticket.service.logout_url, ticket.service.logout_use_iframe,
                    ticket.service.logout_use_iframe_timeout]])
        # Do not the same client for direct calls from the CAS service provider
        # to prevent use of the user session
        client = Client()
        ticket_id = urlparse.parse_qs(response.url.split('?')[1])[constants.TICKET_PARAM][0]
        response = client.get('/idp/cas/serviceValidate', {constants.TICKET_PARAM:
            ticket_id, constants.SERVICE_PARAM: self.URL})
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response['content-type'], 'text/xml')
        constraints = (
                ('/cas:serviceResponse/cas:authenticationSuccess/cas:user',
                    self.LOGIN),
                ('/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:email',
                    self.EMAIL),
        )
        self.assertXPathConstraints(response, constraints, CAS_NAMESPACES)
        # Verify ticket has been deleted
        with self.assertRaises(Ticket.DoesNotExist):
            Ticket.objects.get()

    def test_login_service_validate_without_renew_failure(self):
        response = self.client.get('/idp/cas/login', {constants.SERVICE_PARAM: self.URL})
        self.assertEquals(response.status_code, 302)
        ticket = Ticket.objects.get()
        location = response['Location']
        url = location.split('?')[0]
        query = urlparse.parse_qs(location.split('?')[1])
        self.assertEquals(url, 'http://testserver/login/')
        self.assertIn('nonce', query)
        self.assertIn('next', query)
        self.assertEquals(query['nonce'], [ticket.ticket_id])
        next_url, next_url_query = query['next'][0].split('?')
        next_url_query = urlparse.parse_qs(next_url_query)
        self.assertEquals(next_url, '/idp/cas/continue/')
        self.assertEquals(set(next_url_query.keys()),
                set([constants.SERVICE_PARAM, NONCE_FIELD_NAME]))
        self.assertEquals(next_url_query[constants.SERVICE_PARAM], [self.URL])
        self.assertEquals(next_url_query[NONCE_FIELD_NAME], [ticket.ticket_id])
        response = self.client.post(location, {'login-password-submit': '',
            'username': self.LOGIN, 'password': self.PASSWORD}, follow=False)
        self.assertIn(AUTHENTICATION_EVENTS_SESSION_KEY, self.client.session)
        self.assertIn('nonce', self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0])
        self.assertIn(ticket.ticket_id, self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0]['nonce'])
        self.assertRedirectsComplex(response, query['next'][0], nonce=ticket.ticket_id)
        response = self.client.get(response.url)
        self.assertRedirectsComplex(response, self.URL, ticket=ticket.ticket_id)
        # Check logout state has been updated
        ticket = Ticket.objects.get()
        self.assertIn(constants.SESSION_CAS_LOGOUTS, self.client.session)
        self.assertEquals(self.client.session[constants.SESSION_CAS_LOGOUTS],
                [[ticket.service.name, ticket.service.logout_url, ticket.service.logout_use_iframe,
                    ticket.service.logout_use_iframe_timeout]])
        # Do not the same client for direct calls from the CAS service provider
        # to prevent use of the user session
        client = Client()
        ticket_id = urlparse.parse_qs(response.url.split('?')[1])[constants.TICKET_PARAM][0]
        response = client.get('/idp/cas/serviceValidate', {constants.TICKET_PARAM:
            ticket_id, constants.SERVICE_PARAM: self.URL, constants.RENEW_PARAM: ''})
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response['content-type'], 'text/xml')
        constraints = (
                ('/cas:serviceResponse/cas:authenticationFailure/@code',
                 'INVALID_TICKET_SPEC'),
        )
        self.assertXPathConstraints(response, constraints, CAS_NAMESPACES)
        # Verify ticket has been deleted
        with self.assertRaises(Ticket.DoesNotExist):
            Ticket.objects.get()

    def test_login_proxy_validate_on_service_ticket(self):
        response = self.client.get('/idp/cas/login', {constants.SERVICE_PARAM: self.URL})
        self.assertEquals(response.status_code, 302)
        ticket = Ticket.objects.get()
        location = response['Location']
        url = location.split('?')[0]
        query = urlparse.parse_qs(location.split('?')[1])
        self.assertEquals(url, 'http://testserver/login/')
        self.assertIn('nonce', query)
        self.assertIn('next', query)
        self.assertEquals(query['nonce'], [ticket.ticket_id])
        next_url, next_url_query = query['next'][0].split('?')
        next_url_query = urlparse.parse_qs(next_url_query)
        self.assertEquals(next_url, '/idp/cas/continue/')
        self.assertEquals(set(next_url_query.keys()),
                set([constants.SERVICE_PARAM, NONCE_FIELD_NAME]))
        self.assertEquals(next_url_query[constants.SERVICE_PARAM], [self.URL])
        self.assertEquals(next_url_query[NONCE_FIELD_NAME], [ticket.ticket_id])
        response = self.client.post(location, {'login-password-submit': '',
            'username': self.LOGIN, 'password': self.PASSWORD}, follow=False)
        self.assertIn(AUTHENTICATION_EVENTS_SESSION_KEY, self.client.session)
        self.assertIn('nonce', self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0])
        self.assertIn(ticket.ticket_id, self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0]['nonce'])
        self.assertRedirectsComplex(response, query['next'][0], nonce=ticket.ticket_id)
        response = self.client.get(response.url)
        self.assertRedirectsComplex(response, self.URL, ticket=ticket.ticket_id)
        # Check logout state has been updated
        ticket = Ticket.objects.get()
        self.assertIn(constants.SESSION_CAS_LOGOUTS, self.client.session)
        self.assertEquals(self.client.session[constants.SESSION_CAS_LOGOUTS],
                [[ticket.service.name, ticket.service.logout_url, ticket.service.logout_use_iframe,
                    ticket.service.logout_use_iframe_timeout]])
        # Do not the same client for direct calls from the CAS service provider
        # to prevent use of the user session
        client = Client()
        ticket_id = urlparse.parse_qs(response.url.split('?')[1])[constants.TICKET_PARAM][0]
        response = client.get('/idp/cas/proxyValidate', {constants.TICKET_PARAM:
            ticket_id, constants.SERVICE_PARAM: self.URL})
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response['content-type'], 'text/xml')
        constraints = (
                ('/cas:serviceResponse/cas:authenticationSuccess/cas:user',
                    self.LOGIN),
                ('/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:email',
                    self.EMAIL),
        )
        self.assertXPathConstraints(response, constraints, CAS_NAMESPACES)
        # Verify ticket has been deleted
        with self.assertRaises(Ticket.DoesNotExist):
            Ticket.objects.get()

    @override_settings(A2_IDP_CAS_CHECK_PGT_URL=False)
    def test_proxy(self):
        response = self.client.get('/idp/cas/login', {constants.SERVICE_PARAM: self.URL})
        self.assertEquals(response.status_code, 302)
        ticket = Ticket.objects.get()
        location = response['Location']
        url = location.split('?')[0]
        query = urlparse.parse_qs(location.split('?')[1])
        self.assertEquals(url, 'http://testserver/login/')
        self.assertIn('nonce', query)
        self.assertIn('next', query)
        self.assertEquals(query['nonce'], [ticket.ticket_id])
        next_url, next_url_query = query['next'][0].split('?')
        next_url_query = urlparse.parse_qs(next_url_query)
        self.assertEquals(next_url, '/idp/cas/continue/')
        self.assertEquals(set(next_url_query.keys()),
                set([constants.SERVICE_PARAM, NONCE_FIELD_NAME]))
        self.assertEquals(next_url_query[constants.SERVICE_PARAM], [self.URL])
        self.assertEquals(next_url_query[NONCE_FIELD_NAME], [ticket.ticket_id])
        response = self.client.post(location, {'login-password-submit': '',
            'username': self.LOGIN, 'password': self.PASSWORD}, follow=False)
        self.assertIn(AUTHENTICATION_EVENTS_SESSION_KEY, self.client.session)
        self.assertIn('nonce', self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0])
        self.assertIn(ticket.ticket_id, self.client.session[AUTHENTICATION_EVENTS_SESSION_KEY][0]['nonce'])
        self.assertRedirectsComplex(response, query['next'][0], nonce=ticket.ticket_id)
        response = self.client.get(response.url)
        self.assertRedirectsComplex(response, self.URL, ticket=ticket.ticket_id)
        # Check logout state has been updated
        ticket = Ticket.objects.get()
        self.assertIn(constants.SESSION_CAS_LOGOUTS, self.client.session)
        self.assertEquals(self.client.session[constants.SESSION_CAS_LOGOUTS],
                [[ticket.service.name, ticket.service.logout_url, ticket.service.logout_use_iframe,
                    ticket.service.logout_use_iframe_timeout]])
        # Do not the same client for direct calls from the CAS service provider
        # to prevent use of the user session
        client = Client()
        ticket_id = urlparse.parse_qs(response.url.split('?')[1])[constants.TICKET_PARAM][0]
        response = client.get('/idp/cas/serviceValidate', {constants.TICKET_PARAM:
            ticket_id, constants.SERVICE_PARAM: self.URL, constants.PGT_URL_PARAM: self.PGT_URL})
        for key in client.session.iterkeys():
            if key.startswith(constants.PGT_IOU_PREFIX):
                pgt_iou = key
                pgt = client.session[key]
                break
        else:
            self.assertTrue(False, 'PGTIOU- not found in session')
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response['content-type'], 'text/xml')
        constraints = (
                ('/cas:serviceResponse/cas:authenticationSuccess/cas:user',
                 self.LOGIN),
                ('/cas:serviceResponse/cas:authenticationSuccess/cas:proxyGrantingTicket', pgt_iou),
        )
        self.assertXPathConstraints(response, constraints, CAS_NAMESPACES)
        # Verify service ticket has been deleted
        with self.assertRaises(Ticket.DoesNotExist):
            Ticket.objects.get(ticket_id=ticket_id)
        # Verify pgt ticket exists
        pgt_ticket = Ticket.objects.get(ticket_id=pgt)
        self.assertEquals(pgt_ticket.user, self.user)
        self.assertIsNone(pgt_ticket.expire)
        self.assertEquals(pgt_ticket.service, self.service)
        self.assertEquals(pgt_ticket.service_url, self.URL)
        self.assertEquals(pgt_ticket.proxies, self.PGT_URL)
        # Try to get a proxy ticket for service 2
        # it should fail since no proxy authorization exists
        client = Client()
        response = client.get('/idp/cas/proxy', {
            constants.PGT_PARAM: pgt,
            constants.TARGET_SERVICE_PARAM: self.SERVICE2_URL
        })
        constraints = (
                ('/cas:serviceResponse/cas:proxyFailure/@code',
                 'PROXY_UNAUTHORIZED'),
        )
        self.assertXPathConstraints(response, constraints, CAS_NAMESPACES)
        # Set proxy authorization
        self.service2.proxy.add(self.service)
        # Try again !
        response = client.get('/idp/cas/proxy', {
            constants.PGT_PARAM: pgt,
            constants.TARGET_SERVICE_PARAM: self.SERVICE2_URL
        })
        pt = Ticket.objects.get(ticket_id__startswith=constants.PT_PREFIX)
        self.assertEquals(pt.user, self.user)
        self.assertIsNotNone(pt.expire)
        self.assertEquals(pt.service, self.service2)
        self.assertEquals(pt.service_url, self.SERVICE2_URL)
        self.assertEquals(pt.proxies, self.PGT_URL)
        constraints = (
                ('/cas:serviceResponse/cas:proxySuccess/cas:proxyTicket',
                 pt.ticket_id),
        )
        self.assertXPathConstraints(response, constraints, CAS_NAMESPACES)
        # Now service2 try to resolve the proxy ticket
        client = Client()
        response = client.get('/idp/cas/proxyValidate', {
            constants.TICKET_PARAM: pt.ticket_id,
            constants.SERVICE_PARAM: self.SERVICE2_URL})
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response['content-type'], 'text/xml')
        constraints = (
                ('/cas:serviceResponse/cas:authenticationSuccess/cas:user',
                    self.EMAIL),
                ('/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:username',
                    self.LOGIN),
        )
        self.assertXPathConstraints(response, constraints, CAS_NAMESPACES)
        # Verify ticket has been deleted
        with self.assertRaises(Ticket.DoesNotExist):
            Ticket.objects.get(ticket_id=pt.ticket_id)
        # Check invalidation of PGT when session is closed
        self.client.logout()
        response = client.get('/idp/cas/proxy', {
            constants.PGT_PARAM: pgt,
            constants.TARGET_SERVICE_PARAM: self.SERVICE2_URL
        })
        constraints = (
                ('/cas:serviceResponse/cas:proxyFailure',
                 'session has expired'),
                ('/cas:serviceResponse/cas:proxyFailure/@code',
                 'BAD_PGT'),
        )
        self.assertXPathConstraints(response, constraints, CAS_NAMESPACES)
