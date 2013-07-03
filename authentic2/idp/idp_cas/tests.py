from xml.etree import ElementTree as ET


from django.test import TestCase
from django.test.client import RequestFactory


from authentic2.compat import get_user_model
from .models import CasTicket
from . import views
from . import constants


class CasTests(TestCase):
    LOGIN = 'test'
    PASSWORD = 'test'

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(self.LOGIN, password=self.PASSWORD)
        self.factory = RequestFactory()

    def test_service_validate_with_default_attributes(self):
        CasTicket.objects.create(
                ticket_id='ST-xxx',
                service='yyy',
                user=self.user,
                validity=True)
        request = self.factory.get('/idp/cas/serviceValidate',
                {'service': 'yyy', 'ticket': 'ST-xxx'})
        class TestCasProvider(views.CasProvider):
            def get_attributes(self, request, st):
                assert st.service == 'yyy'
                assert st.ticket_id == 'ST-xxx'
                return { 'username': 'bob', 'email': 'bob@example.com' }, 'default'
        provider = TestCasProvider()
        response = provider.service_validate(request)
        print response.content
        root = ET.fromstring(response.content)
        ns_ctx = { 'cas': constants.CAS_NAMESPACE }
        user_elt = root.find('cas:authenticationSuccess/cas:utilisateur', namespaces=ns_ctx)
        assert user_elt is not None

    def test_service_validate_with_custom_attributes(self):
        CasTicket.objects.create(
                ticket_id='ST-xxx',
                service='yyy',
                user=self.user,
                validity=True)
        request = self.factory.get('/idp/cas/serviceValidate',
                {'service': 'yyy', 'ticket': 'ST-xxx'})
        class TestCasProvider(views.CasProvider):
            def get_attributes(self, request, st):
                assert st.service == 'yyy'
                assert st.ticket_id == 'ST-xxx'
                return { 'username': 'bob', 'email': 'bob@example.com' }, 'utilisateur'
        provider = TestCasProvider()
        response = provider.service_validate(request)
        print response.content
