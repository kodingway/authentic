# -*- coding: utf-8 -*-
import json
import re
import urlparse
from lxml import etree
import base64

import django
from django.core import mail
from django.core.urlresolvers import reverse
from django.test import TestCase
from django.test.client import Client
from django.contrib.auth.hashers import check_password
from django.test.utils import override_settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django import forms
from django.core.serializers.json import DjangoJSONEncoder

from . import hashers, utils, models, decorators, attribute_kinds

def get_response_form(response, form='form'):
    contexts = list(response.context)
    for c in contexts:
        if not form in c:
            continue
        return c[form]

class Authentic2TestCase(TestCase):
    def assertEqualsURL(self, url1, url2, **kwargs):
        '''Check that url1 is equals to url2 augmented with parameters kwargs in its query string.

           The string '*' is a special value, when used it just check that the
           given parameter exist in the first url, it does not check the exact value.
        '''
        splitted1 = urlparse.urlsplit(url1)
        url2 = utils.make_url(url2, params=kwargs)
        splitted2 = urlparse.urlsplit(url2)
        for i, (elt1, elt2) in enumerate(zip(splitted1, splitted2)):
            if i == 3:
                elt1 = urlparse.parse_qs(elt1, True)
                elt2 = urlparse.parse_qs(elt2, True)
                for k, v in elt1.items():
                    elt1[k] = set(v)
                for k, v in elt2.items():
                    if v == ['*']:
                        elt2[k] = elt1.get(k, v)
                    else:
                        elt2[k] = set(v)
            self.assertTrue(elt1 == elt2,
                    "URLs are not equal: %s != %s" % (splitted1, splitted2))

    def assertRedirectsComplex(self, response, expected_url, **kwargs):
        self.assertEquals(response.status_code, 302)
        scheme, netloc, path, query, fragment = urlparse.urlsplit(response.url)
        e_scheme, e_netloc, e_path, e_query, e_fragment = urlparse.urlsplit(expected_url)
        e_scheme = e_scheme if e_scheme else scheme or 'http'
        e_netloc = e_netloc if e_netloc else netloc
        expected_url = urlparse.urlunsplit((e_scheme, e_netloc, e_path, e_query, e_fragment))
        self.assertEqualsURL(response['Location'], expected_url, **kwargs)

    def assertXPathConstraints(self, xml, constraints, namespaces):
        if hasattr(xml, 'content'):
            xml = xml.content
        doc = etree.fromstring(xml)
        for xpath, content in constraints:
            nodes = doc.xpath(xpath, namespaces=namespaces)
            self.assertTrue(len(nodes) > 0, 'xpath %s not found' % xpath)
            for node in nodes:
                if hasattr(node, 'text'):
                    self.assertEqual(node.text, content, 'xpath %s does not contain %s but %s' % (xpath, content, node.text))
                else:
                    self.assertEqual(node, content, 'xpath %s does not contain %s but %s' % (xpath, content, node))


class HashersTests(TestCase):
    def test_sha256_hasher(self):
        hasher = hashers.SHA256PasswordHasher()
        hashed = hasher.encode('admin', '')
        assert hasher.verify('admin', hashed)
        assert hashed == 'sha256$$8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'

    def test_openldap_hashers(self):
        VECTORS = map(str.split, '''\
coin {SHA}NHj+acfc68FPYrMipEBZ3t8ABGY=
250523 {SHA}4zuJhPW1w0upqG7beAlxDcvtBj0=
coin {SSHA}zLPxfZ3RSNkIwVdHWEyB4Tpr6fT9LiVX
coin {SMD5}+x9QkU2T/wlPp6NK3bfYYxPYwaE=
coin {MD5}lqlRm4/d0X6MxLugQI///Q=='''.splitlines())
        for password, oldap_hash in VECTORS:
            dj_hash = hashers.olap_password_to_dj(oldap_hash)
            self.assertTrue(check_password(password, dj_hash))

class SerializerTests(TestCase):
    def test_generic_foreign_key_natural_key(self):
        import json
        from authentic2.models import Attribute, AttributeValue
        from django.contrib.auth import get_user_model
        from django.core import serializers
        User = get_user_model()
        u = User.objects.create(username='john.doe')
        a = Attribute.objects.create(name='phone', label='phone', kind='string')
        av = AttributeValue.objects.create(owner=u, attribute=a, content='0101010101')
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(Attribute.objects.count(), 1)
        self.assertEqual(AttributeValue.objects.count(), 1)
        s = serializers.get_serializer('json')()
        s.serialize([u, a, av], use_natural_foreign_keys=True, use_natural_primary_keys=True)
        result = s.getvalue()
        u.delete()
        a.delete()
        self.assertEqual(User.objects.count(), 0)
        self.assertEqual(Attribute.objects.count(), 0)
        self.assertEqual(AttributeValue.objects.count(), 0)
        expected = [ {
                   'model': 'custom_user.user',
                   'fields': {
                       'uuid': u.uuid,
                       'username': 'john.doe',
                       'email': '',
                       'first_name': '',
                       'last_name': '',
                       'is_active': True,
                       'is_staff': False,
                       'is_superuser': False,
                       'last_login': u.last_login,
                       'date_joined': u.date_joined,
                       'groups': [],
                       'user_permissions': [],
                       'password': '',
                       'ou': None,
                   }
                 },
                  {
                     'model': 'authentic2.attribute',
                     'fields': {
                         'description': '',
                         'name': 'phone',
                         'label': 'phone',
                         'kind': 'string',
                         'user_editable': False,
                         'asked_on_registration': False,
                         'multiple': False,
                         'user_visible': False,
                         'required': False,
                     }
                    },
                 {
                  'model': 'authentic2.attributevalue',
                  'fields': {
                      'owner': [['custom_user', 'user'], [u.uuid]],
                      'attribute': ['phone'],
                      'content': '0101010101',
                  }
                 }
                ]
        expected = json.loads(json.dumps(expected, cls=DjangoJSONEncoder))
        for obj in serializers.deserialize('json', result):
            obj.save()
        self.assertEqual(json.loads(result), expected)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(Attribute.objects.count(), 1)
        self.assertEqual(AttributeValue.objects.count(), 1)


class UtilsTests(Authentic2TestCase):
    def test_assert_equals_url(self):
        self.assertEqualsURL('/test?coin=1&bob=2&coin=3', '/test?bob=2&coin=1&coin=3')

    def test_make_url(self):
        from authentic2.utils import make_url
        self.assertEqualsURL(make_url('../coin'), '../coin')
        self.assertEqualsURL(make_url('../boob', params={'next': '..'}), '../boob?next=..')
        self.assertEqualsURL(make_url('../boob', params={'next': '..'}, append={'xx': 'yy'}), '../boob?xx=yy&next=..')
        self.assertEqualsURL(make_url('../boob', params={'next': '..'}, append={'next': 'yy'}), '../boob?next=..&next=yy')
        self.assertEqualsURL(make_url('auth_login', params={'next': '/zob'}), '/login/?next=%2Fzob')
        self.assertEqualsURL(make_url('auth_login', params={'next': '/zob'}, fragment='a2-panel'), '/login/?next=%2Fzob#a2-panel')

    def test_redirect(self):
        from authentic2.utils import redirect
        from django.test.client import RequestFactory
        rf = RequestFactory()
        request = rf.get('/coin', data={'next': '..'})
        request2 = rf.get('/coin', data={'next': '..', 'token': 'xxx'})
        response = redirect(request, '/boob/', keep_params=True)
        self.assertEqualsURL(response['Location'], '/boob/?next=..')
        response = redirect(request, '/boob/', keep_params=True, exclude=['next'])
        self.assertEqualsURL(response['Location'], '/boob/')
        response = redirect(request2, '/boob/', keep_params=True)
        self.assertEqualsURL(response['Location'], '/boob/?token=xxx&next=..')
        response = redirect(request, '/boob/', keep_params=True, exclude=['token'])
        self.assertEqualsURL(response['Location'], '/boob/?next=..')
        response = redirect(request, '/boob/', keep_params=True, include=['next'])
        self.assertEqualsURL(response['Location'], '/boob/?next=..')
        response = redirect(request, '/boob/', keep_params=True, include=['next'], params={'token': 'uuu'})
        self.assertEqualsURL(response['Location'], '/boob/?token=uuu&next=..')

    def test_redirect_to_login(self):
        from authentic2.utils import redirect_to_login
        from django.test.client import RequestFactory
        rf = RequestFactory()
        request = rf.get('/coin', data={'next': '..'})
        response = redirect_to_login(request)
        self.assertEqualsURL(response['Location'], '/login/?next=..')

    def test_continue_to_next_url(self):
        from authentic2.utils import continue_to_next_url
        from django.test.client import RequestFactory
        rf = RequestFactory()
        request = rf.get('/coin', data={'next': '/zob/', 'nonce': 'xxx'})
        response = continue_to_next_url(request)
        self.assertEqualsURL(response['Location'], '/zob/?nonce=xxx')

    def test_login_require(self):
        from authentic2.utils import login_require
        from django.test.client import RequestFactory
        rf = RequestFactory()
        request = rf.get('/coin', data={'next': '/zob/', 'nonce': 'xxx'})
        response = login_require(request)
        self.assertEqualsURL(response['Location'].split('?', 1)[0], '/login/')
        self.assertEqualsURL(urlparse.parse_qs(response['Location'].split('?', 1)[1])['next'][0], '/coin?nonce=xxx&next=/zob/')

class ValidatorsTest(TestCase):
    def test_validate_password_(self):
        from authentic2.validators import validate_password
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            validate_password('aaaaaZZZZZZ')
        with self.assertRaises(ValidationError):
            validate_password('00000aaaaaa')
        with self.assertRaises(ValidationError):
            validate_password('00000ZZZZZZ')
        validate_password('000aaaaZZZZ')

    @override_settings(A2_PASSWORD_POLICY_REGEX='^[0-9]{8}$',
            A2_PASSWORD_POLICY_REGEX_ERROR_MSG='pasbon',
            A2_PASSWORD_POLICY_MIN_LENGTH=0,
            A2_PASSWORD_POLICY_MIN_CLASSES=0)
    def test_digits_password_policy(self):
        from authentic2.validators import validate_password
        from django.core.exceptions import ValidationError

        with self.assertRaisesRegexp(ValidationError, 'pasbon'):
            validate_password('aaa')
        validate_password('12345678')

def can_resolve_dns():
    '''Verify that DNS resolving is available'''
    import socket
    try:
        return isinstance(socket.gethostbyname('entrouvert.com'), str)
    except:
        return False

@override_settings(A2_VALIDATE_EMAIL_DOMAIN=can_resolve_dns(), LANGUAGE_CODE='en-us')
class RegistrationTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_registration_bad_email(self):
        response = self.client.post(reverse('registration_register'),
                                    {'email': 'fred@0d..be'})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'email', ['Enter a valid email address.'])
        response = self.client.post(reverse('registration_register'),
                                    {'email': u'ééééé'})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'email', ['Enter a valid email address.'])
        response = self.client.post(reverse('registration_register'),
                                    {'email': u''})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'email', ['This field is required.'])

    def test_registration(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        next_url = 'http://relying-party.org/'
        url = utils.make_url('registration_register', params={REDIRECT_FIELD_NAME: next_url})
        response = self.client.post(url, {'email': 'testbot@entrouvert.com'})
        self.assertRedirects(response, reverse('registration_complete'))
        self.assertEqual(len(mail.outbox), 1)
        links = re.findall('https?://.*/', mail.outbox[0].body)
        self.assertIsInstance(links, list) and self.assertIsNot(links, [])
        link = links[0]
        response = self.client.get(link)
        self.assertEqual(response.status_code, 200)
        response = self.client.post(link, { 'password1': 'toto',
                                            'password2': 'toto'})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'password1', ['password must contain at least 6 characters'])

        response = self.client.post(link, { 'password1': 'T0toto',
                                            'password2': 'T0toto'})
        new_user = User.objects.get()
        self.assertRedirects(response, next_url)
        self.assertEqual(new_user.email, 'testbot@entrouvert.com')
        self.assertIsNone(new_user.username)
        self.assertTrue(new_user.check_password('T0toto'))
        self.assertTrue(new_user.is_active)
        self.assertFalse(new_user.is_staff)
        self.assertFalse(new_user.is_superuser)
        self.assertEqual(str(self.client.session['_auth_user_id']), str(new_user.pk))
        client = Client()
        response = client.post('/login/', {
                'username': 'testbot@entrouvert.com',
                'password': 'T0toto',
                'login-password-submit': '1'
        })
        self.assertRedirects(response, '/')

    @override_settings(A2_REGISTRATION_FORM_USERNAME_REGEX=r'^(ab)+$',
            A2_REGISTRATION_FORM_USERNAME_LABEL='Identifiant',
            A2_REGISTRATION_FORM_USERNAME_HELP_TEXT='Bien remplir',
            A2_REGISTRATION_FIELDS=['username'],
            A2_REQUIRED_FIELDS=['username'])
    def test_username_settings(self):
        response = self.client.post(reverse('registration_register'),
                                    {'email': 'testbot@entrouvert.com'})
        self.assertRedirects(response, reverse('registration_complete'))
        self.assertEqual(len(mail.outbox), 1)
        links = re.findall('https?://.*/', mail.outbox[0].body)
        self.assertIsInstance(links, list) and self.assertIsNot(links, [])
        link = links[0]
        response = self.client.get(link)
        form = get_response_form(response)
        self.assertEqual(set(form.fields), set(['username', 'password1', 'password2']))
        self.assertEqual(set(field for field in form.fields if
                    form.fields[field].required), set(['username',
                        'password1', 'password2']))
        self.assertEqual(form.fields['username'].label, 'Identifiant')
        self.assertEqual(form.fields['username'].help_text, 'Bien remplir')
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'username', [])
        response = self.client.post(link, {'username': 'abx',
                'password1': 'Coucou1', 'password2': 'Coucou1'})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'username', ['Enter a valid value.'])
        response = self.client.post(link, {'username': 'abab',
                'password1': 'Coucou1', 'password2': 'Coucou1'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('auth_homepage'))

    @override_settings(A2_REGISTRATION_FIELDS=['username'],
            A2_REQUIRED_FIELDS=['username'],
            A2_USERNAME_IS_UNIQUE=True)
    def test_username_is_unique(self):
        client = Client()
        response = client.post(reverse('registration_register'),
                                    {'email': 'testbot@entrouvert.com'})
        self.assertRedirects(response, reverse('registration_complete'))
        self.assertEqual(len(mail.outbox), 1)
        links = re.findall('https?://.*/', mail.outbox[0].body)
        self.assertIsInstance(links, list) and self.assertIsNot(links, [])
        link = links[0]
        response = client.get(link)
        form = get_response_form(response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(form.fields), set(['username', 'password1', 'password2']))
        self.assertEqual(set(field for field in form.fields if
                    form.fields[field].required), set(['username',
                        'password1', 'password2']))
        response = client.post(link, {'username': 'john.doe',
                'password1': 'Coucou1', 'password2': 'Coucou1'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('auth_homepage'))
        # new session
        client = Client()
        response = client.post(link, {'username': 'john.doe',
                'password1': 'Coucou1', 'password2': 'Coucou1'})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'username', ['This username is already in use. Please supply a different username.'])

    @override_settings(A2_EMAIL_IS_UNIQUE=True)
    def test_email_is_unique(self):
        response = self.client.post(reverse('registration_register'),
                                    {'email': 'testbot@entrouvert.com'})
        self.assertRedirects(response, reverse('registration_complete'))
        self.assertEqual(len(mail.outbox), 1)
        links = re.findall('https?://.*/', mail.outbox[0].body)
        self.assertIsInstance(links, list) and self.assertIsNot(links, [])
        link = links[0]
        response = self.client.get(link)
        form = get_response_form(response)
        self.assertEqual(set(form.fields), set(['password1', 'password2']))
        self.assertEqual(set(field for field in form.fields if
                    form.fields[field].required), set(['password1', 'password2']))
        self.assertEqual(response.status_code, 200)
        response = self.client.post(link, {'password1': 'Coucou1',
                'password2': 'Coucou1'})
        self.assertRedirects(response, reverse('auth_homepage'))
        client = Client()
        response = client.post(link, {'password1': 'Coucou1',
                'password2': 'Coucou1'})
        self.assertRedirects(response, link, fetch_redirect_response=False)
        response = self.client.get(link)
        self.assertRedirects(response, reverse('auth_homepage'))
        response = self.client.post(reverse('registration_register'),
                                    {'email': 'testbot@entrouvert.com'})
        self.assertFormError(response, 'form', 'email',
            ['This email address is already in use. Please supply a different '
             'email address.'])


    def test_attribute_model(self):
        models.Attribute.objects.create(
                label=u'Prénom',
                name='prenom',
                required=True,
                kind='string')
        models.Attribute.objects.create(
                label=u'Nom',
                name='nom',
                asked_on_registration=True,
                user_visible=True,
                kind='string')
        models.Attribute.objects.create(
                label='Profession',
                name='profession',
                user_editable=True,
                kind='string')
        response = self.client.post(reverse('registration_register'),
                                    {'email': 'testbot@entrouvert.com'})
        self.assertRedirects(response, reverse('registration_complete'))
        self.assertEqual(len(mail.outbox), 1)
        links = re.findall('https?://.*/', mail.outbox[0].body)
        self.assertIsInstance(links, list) and self.assertIsNot(links, [])
        link = links[0]
        response = self.client.get(link)
        form = get_response_form(response)
        self.assertEqual(set(form.fields), set(['prenom', 'nom', 'password1', 'password2']))
        self.assertEqual(set(field for field in form.fields if
                    form.fields[field].required), set(['prenom', 'password1', 'password2']))
        self.assertEqual(response.status_code, 200)
        response = self.client.post(link, {'prenom': 'John',
                'nom': 'Doe',
                'password1': 'Coucou1',
                'password2': 'Coucou1'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('auth_homepage'))
        response = self.client.get(reverse('account_management'))
        self.assertContains(response, 'Nom')
        self.assertNotContains(response, 'Prénom')
        response = self.client.get(reverse('profile_edit'))
        form = get_response_form(response)
        self.assertEqual(set(form.fields), set(['profession']))
        self.assertEqual(set(field for field in form.fields if
                    form.fields[field].required), set())
        response = self.client.post(reverse('profile_edit'), {'profession': 'pompier'})
        self.assertRedirects(response, reverse('account_management'))
        response = self.client.get(reverse('account_management'))
        self.assertContains(response, 'Nom')
        self.assertContains(response, 'Doe')
        self.assertNotContains(response, 'Profession')
        self.assertNotContains(response, 'pompier')
        self.assertNotContains(response, 'Prénom')
        self.assertNotContains(response, 'John')


class UserProfileTests(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = User.objects.create(username='testbot')
        user.set_password('secret')
        user.save()
        self.client = Client()

    def test_edit_profile_attributes(self):

        models.Attribute.objects.create(
            label=u'custom',
            name='custom',
            required=True,
            user_visible=True,
            user_editable=True,
            kind='string')
        models.Attribute.objects.create(
            label=u'ID',
            name='national_number',
            user_editable=True,
            user_visible=True,
            kind='string')
        self.assertTrue(self.client.login(username='testbot', password='secret'))

        # get the edit page in order to check form's prefix
        response = self.client.get(reverse('profile_edit'))
        form = get_response_form(response)

        kwargs = {'custom': 'random data',
                  'national_number': 'xx20153566342yy'}
        if form.prefix:
            kwargs = dict(('%s-%s' % (form.prefix, k), v)
                          for k, v in kwargs.iteritems())

        response = self.client.post(reverse('profile_edit'), kwargs)

        self.assertEqual(response.status_code, 302)
        response = self.client.get(reverse('account_management'))
        self.assertContains(response, 'random data')
        self.assertContains(response, 'xx20153566342yy')

        response = self.client.get(reverse('profile_edit'))
        form = get_response_form(response)
        self.assertEqual(form['custom'].value(), 'random data')
        self.assertEqual(form['national_number'].value(), 'xx20153566342yy')

    def test_noneditable_profile_attributes(self):
        """
        tests if user non editable attributes do not appear in profile form
        """

        models.Attribute.objects.create(
            label=u'custom',
            name='custom',
            required=False,
            user_editable=False,
            kind='string')
        models.Attribute.objects.create(
            label=u'ID',
            name='national_number',
            user_editable=False,
            user_visible=False,
            kind='string')

        self.assertTrue(self.client.login(username='testbot', password='secret'))
        response = self.client.get(reverse('profile_edit'))
        form = get_response_form(response)
        self.assertEqual(set(form.fields), set())


class CacheTests(TestCase):
    urls = 'authentic2.cache_tests_urls'

    def test_cache_decorator_base(self):
        import random
        from authentic2.decorators import CacheDecoratorBase

        class GlobalCache(CacheDecoratorBase):
            def __init__(self, *args, **kwargs):
                self.cache = {}
                super(GlobalCache, self).__init__(*args, **kwargs)

            def set(self, key, value):
                self.cache[key] = value

            def get(self, key):
                return self.cache.get(key, (None, None))

            def delete(self, key, value):
                if key in self.cache and self.cache[key] == value:
                    del self.cache[key]

        def f():
            return random.random()
        # few chances the same value comme two times in a row
        self.assertNotEquals(f(), f())

        # with cache the same value will come back
        g = GlobalCache(f)
        values = set()
        for x in range(10):
            values.add(g())
        self.assertEquals(len(values), 1)
        # null timeout, no cache
        h = GlobalCache(timeout=0)(f)
        self.assertNotEquals(h(), h())

    def test_django_cache(self):
        client = Client()
        response1 = client.get('/cache/', HTTP_HOST='cache1.example.com')
        response2 = client.get('/cache/', HTTP_HOST='cache2.example.com')
        response3 = client.get('/cache/', HTTP_HOST='cache1.example.com')
        self.assertNotEqual(response1.content, response2.content)
        self.assertEqual(response1.content, response3.content)

class AttributeKindsTest(TestCase):
    def test_simple(self):
        from django.core.exceptions import ValidationError
        from django import forms

        with self.settings(A2_ATTRIBUTE_KINDS=[
                {
                    'label': 'integer',
                    'name': 'integer',
                    'field_class': forms.IntegerField,
                }]):
            title_field = attribute_kinds.get_form_field('title')
            self.assertTrue(isinstance(title_field, forms.ChoiceField))
            self.assertTrue(isinstance(title_field.widget, forms.RadioSelect))
            self.assertIsNotNone(title_field.choices)
            self.assertTrue(isinstance(attribute_kinds.get_form_field('string'),
                    forms.CharField))
            self.assertEqual(attribute_kinds.get_kind('string')['name'],
                    'string')
            self.assertTrue(isinstance(attribute_kinds.get_form_field('integer'),
                    forms.IntegerField))
            self.assertEqual(attribute_kinds.get_kind('integer')['name'],
                    'integer')
            attribute_kinds.validate_siret('49108189900024')
            with self.assertRaises(ValidationError):
                attribute_kinds.validate_siret('49108189900044')
        with self.assertRaises(KeyError):
            attribute_kinds.get_form_field('integer')
        with self.assertRaises(KeyError):
            attribute_kinds.get_kind('integer')
        fields = {}
        for i, name in enumerate(attribute_kinds.get_attribute_kinds()):
            fields['field_%d' % i] = attribute_kinds.get_form_field(name)
        AttributeKindForm = type('AttributeKindForm', (forms.Form,), fields)
        unicode(AttributeKindForm().as_p())

@override_settings(A2_REQUIRED_FIELDS=['username'])
class APITest(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model
        from django_rbac.utils import get_role_model, get_ou_model
        from django.contrib.contenttypes.models import ContentType
        User = get_user_model()
        Role = get_role_model()
        OU = get_ou_model()

        ct_user = ContentType.objects.get_for_model(User)

        self.ou = OU.objects.create(slug='ou', name='OU')
        self.reguser1 = User.objects.create(username='reguser1')
        self.reguser1.set_password('password')
        self.reguser1.save()
        self.user_admin_role = Role.objects.get_admin_role(
            instance=ct_user, name='user admin', slug='user-admin')
        self.reguser1.roles.add(self.user_admin_role)

        self.reguser2 = User.objects.create(username='reguser2',
                                            password='password')
        self.reguser2.set_password('password')
        self.reguser2.save()
        self.ou_user_admin_role = Role.objects.get_admin_role(
            instance=ct_user, name='user admin', slug='user-admin',
            ou=self.ou)
        self.ou_user_admin_role.members.add(self.reguser2)

        self.reguser3 = User.objects.create(username='reguser3',
                                            password='password',
                                            is_superuser=True)
        self.reguser3.set_password('password')
        self.reguser3.save()

    def test_register_reguser1(self):
        self.register_with_user(self.reguser1)

    def test_register_reguser2(self):
        self.register_with_user(self.reguser2)

    def test_register_reguser3(self):
        self.register_with_user(self.reguser3)

    def register_with_user(self, user):
        from django.contrib.auth import get_user_model
        from rest_framework import test
        from rest_framework import status
        User = get_user_model()
        user_count = User.objects.count()
        client = test.APIClient()
        password = '12XYab'
        username = 'john.doe'
        email = 'john.doe@example.com'
        return_url = 'http://sp.org/register/'
        payload = {
            'email': email,
            'username': username,
            'ou': self.ou.slug,
            'password': password,
            'return_url': return_url,
        }
        outbox_level = len(mail.outbox)
        cred = base64.b64encode('%s:%s' % (user.username.encode('utf-8'), 'password'))
        client.credentials(HTTP_AUTHORIZATION='Basic %s' % cred)
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('result', response.data)
        self.assertEqual(response.data['result'], 1)
        self.assertIn('token', response.data)
        token = response.data['token']
        self.assertIn('request', response.data)
        self.assertEqual(response.data['request'], payload)
        self.assertEqual(len(mail.outbox), outbox_level+1)

        # User side
        client = Client()
        activation_mail = mail.outbox[-1]
        m = re.search('https?://[^\n ]*', activation_mail.body)
        self.assertNotEqual(m, None)
        activation_url = m.group()
        response = client.get(activation_url)
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertEqual(response['Location'], utils.make_url(return_url, params={'token': token}))
        self.assertEqual(User.objects.count(), user_count+1)
        response = client.get(reverse('auth_homepage'))
        self.assertContains(response, username)
        last_user = User.objects.order_by('id').last()
        self.assertEqual(last_user.username, username)
        self.assertEqual(last_user.email, email)
        self.assertEqual(last_user.ou.slug, self.ou.slug)
        self.assertTrue(last_user.check_password(password))
