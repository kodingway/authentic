import base64
import unittest
import StringIO
import urlparse
from lxml.html import parse

from django.test import Client
from django.test.utils import override_settings
from django.contrib.auth import get_user_model, REDIRECT_FIELD_NAME
from django.core.urlresolvers import reverse
from django.utils.translation import gettext as _

from authentic2.tests import Authentic2TestCase
from authentic2.saml import models as saml_models
from authentic2.a2_rbac.models import Role, OrganizationalUnit

try:
    import lasso
except ImportError:
    lasso = None


@unittest.skipUnless(lasso is not None, 'lasso is not installed')
@override_settings(A2_IDP_SAML2_ENABLE=True)
class SamlBaseTestCase(Authentic2TestCase):
    METADATA_TPL = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor
 entityID="{base_url}/"
 xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
 <SPSSODescriptor
   AuthnRequestsSigned="true"
   WantAssertionsSigned="true"
   protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
   <SingleLogoutService
     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
     Location="https://files.entrouvert.org/mellon/logout" />
   <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
   <AssertionConsumerService
     index="0"
     isDefault="true"
     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
     Location="{base_url}/sso/POST" />
   <AssertionConsumerService
     index="1"
     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
     Location="{base_url}/mellon/artifactResponse" />
 </SPSSODescriptor>
</EntityDescriptor>'''

    def get_sp_metadata(self, base_url='https://sp.example.com'):
        return self.METADATA_TPL.format(base_url=base_url)

    def get_idp_metadata(self):
        client = Client()
        response = client.get(reverse('a2-idp-saml-metadata'))
        # FIXME: add better test of well formedness for metadata
        self.assertEqual(response['Content-type'], 'text/xml',
                         msg='metadata endpoint did not return an XML '
                         'document')
        self.assertIn('IDPSSODescriptor', response.content,
                      msg='metadata endpoint does not contain an '
                      'IDPSSODescriptor  element')
        return response.content

    def get_server(self, base_url='https://sp.example.com'):
        sp_meta = self.get_sp_metadata(base_url=base_url)
        idp_meta = self.get_idp_metadata()
        server = lasso.Server.newFromBuffers(sp_meta)
        server.addProviderFromBuffer(lasso.PROVIDER_ROLE_IDP, idp_meta)
        return server

    def setUp(self):
        self.base_url = 'https://sp.example.com'
        self.name = 'Test SP'
        self.slug = 'test-sp'
        self.email = 'john.doe@example.com'
        self.username = 'john.doe'
        self.first_name = 'John'
        self.last_name = 'Doe'
        self.password = 'T0toto'
        self.user = get_user_model().objects.create(
            email=self.email,
            username=self.username,
            first_name=self.first_name,
            last_name=self.last_name)
        self.user.set_password(self.password)
        self.user.save()
        self.default_ou = OrganizationalUnit.objects.get()
        sp_meta = self.get_sp_metadata()
        self.liberty_provider = saml_models.LibertyProvider(
            name=self.name,
            slug=self.slug,
            ou=self.default_ou,
            metadata=sp_meta)
        self.liberty_provider.clean()
        self.liberty_provider.save()
        self.liberty_service_provider = saml_models.LibertyServiceProvider \
            .objects.create(
                liberty_provider=self.liberty_provider,
                enabled=True)
        self.default_sp_options_idp_policy = saml_models.SPOptionsIdPPolicy \
            .objects.create(
                name='Default',
                enabled=True,
                authn_request_signed=False,
                default_name_id_format='persistent',
                accepted_name_id_format=['persistent'])
        self.admin_role = Role.objects.create(
            name='Administrator',
            slug='administrator',
            service=self.liberty_provider)
        self.admin_role.attributes.create(
            name='superuser',
            kind='strig',
            value='true')
        self.admin_role.members.add(self.user)
        self.first_name_attribute = self.liberty_provider.attributes.create(
            name_format='basic',
            name='first-name',
            friendly_name='First name',
            attribute_name='django_user_first_name')
        self.last_name_attribute = self.liberty_provider.attributes.create(
            name_format='basic',
            name='last-name',
            friendly_name='Last name',
            attribute_name='django_user_last_name')
        self.superuser_attribute = self.liberty_provider.attributes.create(
            name_format='basic',
            name='superuser',
            friendly_name='Superuser status',
            attribute_name='superuser')

    def make_authn_request(
            self, idp=None,
            method=lasso.HTTP_METHOD_REDIRECT,
            allow_create=None,
            format=None,
            relay_state=None,
            force_authn=None,
            is_passive=None,
            sp_name_qualifier=None,
            sign=False):
        server = self.get_server()
        login = lasso.Login(server)
        if not sign:
            login.setSignatureHint(lasso.PROFILE_SIGNATURE_HINT_FORBID)
        login.initAuthnRequest(idp, method)
        request = login.request
        policy = request.nameIdPolicy
        if force_authn is not None:
            request.forceAuthn = force_authn
        if is_passive is not None:
            request.isPassive = is_passive
        if allow_create is not None:
            policy.allowCreate = allow_create
        if format is not None:
            policy.format = format
        if sp_name_qualifier is not None:
            policy.spNameQualifier = sp_name_qualifier
        if relay_state is not None:
            login.msgRelayState = relay_state
        login.buildAuthnRequestMsg()
        if method == lasso.HTTP_METHOD_REDIRECT:
            self.assertIsNone(login.msgBody, 'body should be None with '
                              'method Redirect')
        elif method == lasso.HTTP_METHOD_POST:
            self.assertIsNotNone(login.msgBody)
        self.assertIsNone(login.msgBody, 'body should be None with method '
                          'Redirect')
        url_parsed = urlparse.urlparse(login.msgUrl)
        self.assertEqual(url_parsed.path, reverse('a2-idp-saml-sso'),
                         'msgUrl should target the sso endpoint')
        return login.msgUrl, login.msgBody

    def parse_authn_response(self, saml_response):
        server = self.get_server()
        login = lasso.Login(server)
        login.processAuthnResponseMsg(saml_response)
        login.acceptSso()
        return login


class SamlSSOTestCase(SamlBaseTestCase):
    def test_sso_login_redirect(self):
        client = Client()
        # Launch an AuthnRequest
        url, body = self.make_authn_request(allow_create=True)
        response = client.get(url)
        self.assertRedirectsComplex(response, reverse('auth_login'), **{
            'nonce': '*',
            REDIRECT_FIELD_NAME: reverse('a2-idp-saml-continue'),
        })
        nonce = urlparse.parse_qs(
            urlparse.urlparse(
                response['Location']).query)['nonce'][0]
        url = response['Location']
        response = client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'].split(';')[0], 'text/html')
        self.assertInHTML(u'<input type="submit" name="cancel" '
                          'value="%s"/>' % _('Cancel'), response.content,
                          count=1)
        response = client.post(url, {
            'username': self.email,
            'password': self.password,
            'login-password-submit': 1,
        })
        self.assertRedirectsComplex(
            response, reverse('a2-idp-saml-continue'), nonce=nonce)
        response = client.get(response['Location'])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-type'].split(';')[0], 'text/html')
        doc = parse(StringIO.StringIO(response.content)).getroot()
        self.assertEqual(len(doc.forms), 1, msg='the number of forms is not 1')
        self.assertEqual(
            doc.forms[0].get('action'), '%s/sso/POST' % self.base_url)
        self.assertIn('SAMLResponse', doc.forms[0].fields)
        saml_response = doc.forms[0].fields['SAMLResponse']
        try:
            base64.b64decode(saml_response)
        except TypeError:
            self.fail('SAMLResponse is not base64 encoded: %s' % saml_response)
        login = self.parse_authn_response(saml_response)
        assertion = login.assertion
        federation = saml_models.LibertyFederation.objects.get()
        assertion_xml = assertion.exportToXml()
        namespaces = {
            'saml': lasso.SAML2_ASSERTION_HREF,
        }
        print assertion_xml
        constraints = (
            ('/saml:Assertion/saml:Subject/saml:NameID',
                federation.name_id_content),
            ('/saml:Assertion/saml:Subject/saml:NameID/@Format',
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT),
            ('/saml:Assertion/saml:Subject/saml:NameID/@SPNameQualifier',
                '%s/' % self.base_url),

            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='first-name']/"
                "@NameFormat", lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC),
            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='first-name']/"
                "@FriendlyName", 'First name'),
            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='first-name']/"
                "saml:AttributeValue", 'John'),

            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='last-name']/"
                "@NameFormat", lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC),
            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='last-name']/"
                "@FriendlyName", 'Last name'),
            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='last-name']/"
                "saml:AttributeValue", 'Doe'),

            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='superuser']/"
                "@NameFormat", lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC),
            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='superuser']/"
                "@FriendlyName", 'Superuser status'),
            ("/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='superuser']/"
                "saml:AttributeValue", 'true'),
        )
        self.assertXPathConstraints(assertion_xml, constraints, namespaces)

    def test_sso_cancel_redirect(self):
        client = Client()
        # Launch an AuthnRequest
        url, body = self.make_authn_request(allow_create=True)
        response = client.get(url)
        self.assertRedirectsComplex(response, reverse('auth_login'), **{
                'nonce': '*',
                REDIRECT_FIELD_NAME: reverse('a2-idp-saml-continue'),
        })
        nonce = urlparse.parse_qs(urlparse.urlparse(response['Location']).query)['nonce'][0]
        url = response['Location']
        response = client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'].split(';')[0], 'text/html')
        self.assertInHTML(u'<input type="submit" name="cancel" value="%s"/>' % _('Cancel'), response.content, count=1)
        response = client.post(url, {
                'cancel': 1,
        })
        self.assertRedirectsComplex(response, reverse('a2-idp-saml-continue'), cancel='*', nonce=nonce)
        response = client.get(response['Location'])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-type'].split(';')[0], 'text/html')
        doc = parse(StringIO.StringIO(response.content)).getroot()
        self.assertEqual(len(doc.forms), 1, msg='the number of forms is not 1')
        self.assertEqual(doc.forms[0].get('action'), '%s/sso/POST' % self.base_url)
        self.assertIn('SAMLResponse', doc.forms[0].fields)
        saml_response = doc.forms[0].fields['SAMLResponse']
        try:
            base64.b64decode(saml_response)
        except TypeError:
            self.fail('SAMLResponse is not base64 encoded: %s' % saml_response)
        with self.assertRaises(lasso.ProfileRequestDeniedError):
            assertion = self.parse_authn_response(saml_response)

    def test_sso_login_redirect_attributes(self):
        client = Client()
        # Launch an AuthnRequest
        url, body = self.make_authn_request(allow_create=True)
        response = client.get(url)
        self.assertRedirectsComplex(response, reverse('auth_login'), **{
                'nonce': '*',
                REDIRECT_FIELD_NAME: reverse('a2-idp-saml-continue'),
        })
        nonce = urlparse.parse_qs(urlparse.urlparse(response['Location']).query)['nonce'][0]
        url = response['Location']
        response = client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'].split(';')[0], 'text/html')
        self.assertInHTML(u'<input type="submit" name="cancel" value="%s"/>' % _('Cancel'), response.content, count=1)
        response = client.post(url, {
                'username': self.email,
                'password': self.password,
                'login-password-submit': 1,
        })
        self.assertRedirectsComplex(response, reverse('a2-idp-saml-continue'), nonce=nonce)
        response = client.get(response['Location'])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-type'].split(';')[0], 'text/html')
        doc = parse(StringIO.StringIO(response.content)).getroot()
        self.assertEqual(len(doc.forms), 1, msg='the number of forms is not 1')
        self.assertEqual(doc.forms[0].get('action'), '%s/sso/POST' % self.base_url)
        self.assertIn('SAMLResponse', doc.forms[0].fields)
        saml_response = doc.forms[0].fields['SAMLResponse']
        try:
            base64.b64decode(saml_response)
        except TypeError:
            self.fail('SAMLResponse is not base64 encoded: %s' % saml_response)
        login = self.parse_authn_response(saml_response)
        assertion = login.assertion
        federation = saml_models.LibertyFederation.objects.get()
        assertion_xml = assertion.exportToXml()
        def lasso_elt(elt):
            return '{%s}%s' % (lasso.SAML2_ASSERTION_HREF, elt)
        namespaces = {
            'saml': lasso.SAML2_ASSERTION_HREF,
        }
        constraints = (
            ('/saml:Assertion/saml:Subject/saml:NameID',
                federation.name_id_content),
            ('/saml:Assertion/saml:Subject/saml:NameID/@Format',
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT),
            ('/saml:Assertion/saml:Subject/saml:NameID/@SPNameQualifier',
                '%s/' % self.base_url),
        )
        self.assertXPathConstraints(assertion_xml, constraints, namespaces)
