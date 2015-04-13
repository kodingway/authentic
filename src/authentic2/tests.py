# -*- coding: utf-8 -*-
import re
import urlparse
from xml.etree import ElementTree as ET

import django
from django.core import mail
from django.core.urlresolvers import reverse
from django.test import TestCase
from django.test.client import Client
from django.contrib.auth.hashers import check_password
from django.test.utils import override_settings

from . import hashers, utils

class Authentic2TestCase(TestCase):
    def assertEqualsURL(self, url1, url2, **kwargs):
        splitted1 = urlparse.urlsplit(url1)
        url2 = utils.make_url(url2, params=kwargs)
        splitted2 = urlparse.urlsplit(url2)
        for i, (elt1, elt2) in enumerate(zip(splitted1, splitted2)):
            if i == 3:
                elt1 = urlparse.parse_qs(elt1)
                elt2 = urlparse.parse_qs(elt2)
                for k, v in elt1.items():
                    elt1[k] = set(v)
                for k, v in elt2.items():
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

    def assertEqualsXML(self, xml, constraints):
        '''Check XML content for contraints.

           xml can be a string, a Response object or an element tree object.

           constraints is a sequence of 3-tuple:
            - first tuple is an element tree XPath or a sequence of element
              names which will be concatenated to build the XPath,
            - second is an eventual text content to check, can be None,
            - third is an eventual dictionnary made of attribute names and
              attribute value, can be None.
        '''
        if hasattr(xml, 'content'):
            xml = xml.content
        if isinstance(xml, basestring):
            doc = ET.fromstring(xml)
        else:
            doc = xml
        for path, content, attributes in constraints:
            if isinstance(path, tuple):
                path = './' + '/'.join(path)
            elt = doc.find(path)
            self.assertIsNotNone(elt, "path %s not found" % path)
            if content:
                self.assertEquals(elt.text, content)
            if attributes:
                for key, value in attributes.iteritems():
                    self.assertIn(key, elt.attrib, "attribute %s missing on %s" % (key, path))
                    self.assertEquals(elt.attrib[key], value, "attribute %s value is not expected: %s != %s" %
                            (key, elt.attrib[key], value))


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
        from django.contrib.auth.models import User
        from django.core import serializers
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
                   'model': 'auth.user',
                   'fields': {
                       'username': 'john.doe',
                       'email': '',
                       'first_name': '',
                       'last_name': '',
                       'is_active': True,
                       'is_staff': False,
                       'is_superuser': False,
                       'last_login': u.last_login.isoformat()[:-3],
                       'date_joined': u.date_joined.isoformat()[:-3],
                       'groups': [],
                       'user_permissions': [],
                       'password': '',
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
                      'owner': [['auth', 'user'], ['john.doe']],
                      'attribute': ['phone'],
                      'content': '0101010101',
                  }
                 }
                ]
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
        self.assertContains(response, '<ul class="errorlist"><li>Enter a valid email address.</li></ul>', count=1, html=True)
        response = self.client.post(reverse('registration_register'),
                                    {'email': u'ééééé'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<ul class="errorlist"><li>Enter a valid email address.</li></ul>', count=1, html=True)
        response = self.client.post(reverse('registration_register'),
                                    {'email': u''})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<ul class="errorlist"><li>This field is required.</li></ul>', count=1, html=True)

    def test_registration(self):
        response = self.client.post(reverse('registration_register'),
                                    {'email': 'testbot@entrouvert.com'})
        self.assertRedirects(response, reverse('registration_complete'))
        self.assertEqual(len(mail.outbox), 1)
        links = re.findall('https?://.*/', mail.outbox[0].body)
        self.assertIsInstance(links, list) and self.assertIsNot(links, [])
        link = links[0]
        completion = self.client.get(link)
        self.assertEqual(completion.status_code, 200)
        self.bad_password_test(link)
        self.good_password_test(link)
        mail.outbox = []

    def bad_password_test(self, url):
        """
        test short filled password
        """
        completion = self.client.post(url, {'first_name': 'Test',
                                            'last_name': 'User',
                                            'password1': 'toto',
                                            'password2': 'toto'})
        self.assertEqual(completion.status_code, 200)

    def good_password_test(self, url):
        completion = self.client.post(url, {'first_name': 'Test',
                                            'last_name': 'User',
                                            'password1': 'T0toto',
                                            'password2': 'T0toto'})
        self.assertEqual(completion.status_code, 302)

class CacheTests(TestCase):
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


