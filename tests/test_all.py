# -*- coding: utf-8 -*-
import json
import re
import urlparse
import base64

from django.core import mail
from django.core.urlresolvers import reverse
from django.test import TestCase
from django.test.client import Client
from django.test.utils import override_settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.serializers.json import DjangoJSONEncoder
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import ugettext as _

from rest_framework import test
from rest_framework import status

from django_rbac.utils import get_role_model, get_ou_model

from authentic2 import utils, models, attribute_kinds

from utils import Authentic2TestCase, get_response_form, can_resolve_dns


class SerializerTests(TestCase):
    def test_generic_foreign_key_natural_key(self):
        import json
        from authentic2.models import Attribute, AttributeValue
        from django.core import serializers
        User = get_user_model()
        ucount = User.objects.count()
        acount = Attribute.objects.count()
        u = User.objects.create(username='john.doe')
        avcount = AttributeValue.objects.count()
        a = Attribute.objects.create(name='phone', label='phone',
                                     kind='string')
        av = AttributeValue.objects.create(owner=u, attribute=a,
                                           content='0101010101')
        self.assertEqual(User.objects.count(), ucount + 1)
        self.assertEqual(Attribute.objects.count(), acount + 1)
        self.assertEqual(AttributeValue.objects.count(), avcount + 1)
        s = serializers.get_serializer('json')()
        s.serialize([u, a, av], use_natural_foreign_keys=True,
                    use_natural_primary_keys=True)
        result = s.getvalue()
        u.delete()
        a.delete()
        self.assertEqual(User.objects.count(), ucount)
        self.assertEqual(Attribute.objects.count(), acount)
        self.assertEqual(AttributeValue.objects.count(), 0)
        expected = [
            {
                'model': 'custom_user.user',
                'fields': {
                    'uuid': u.uuid,
                    'email_verified': False,
                    'username': 'john.doe',
                    'email': '',
                    'first_name': '',
                    'last_name': '',
                    'is_active': True,
                    'is_staff': False,
                    'is_superuser': False,
                    'last_login': u.last_login,
                    'date_joined': u.date_joined,
                    'modified': u.modified,
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
                    'disabled': False,
                    'searchable': False,
                    'order': 0,
                }
            },
            {
                'model': 'authentic2.attributevalue',
                'fields': {
                    'owner': [['custom_user', 'user'], [u.uuid]],
                    'attribute': ['phone'],
                    'content': '0101010101',
                    'multiple': False,
                    'verified': False,
                }
            }
        ]
        expected = json.loads(json.dumps(expected, cls=DjangoJSONEncoder))
        for obj in serializers.deserialize('json', result):
            obj.save()
        self.assertEqual(json.loads(result), expected)
        self.assertEqual(User.objects.count(), ucount + 1)
        self.assertEqual(Attribute.objects.count(), acount + 1)
        # first_name and last_name attribute value not recreated since they were not dumped
        self.assertEqual(AttributeValue.objects.count(), 1)


class UtilsTests(Authentic2TestCase):
    def test_assert_equals_url(self):
        self.assertEqualsURL('/test?coin=1&bob=2&coin=3',
                             '/test?bob=2&coin=1&coin=3')

    def test_make_url(self):
        from authentic2.utils import make_url
        self.assertEqualsURL(make_url('../coin'), '../coin')
        self.assertEqualsURL(make_url('../boob', params={'next': '..'}),
                             '../boob?next=..')
        self.assertEqualsURL(make_url('../boob', params={'next': '..'},
                                      append={'xx': 'yy'}),
                             '../boob?xx=yy&next=..')
        self.assertEqualsURL(make_url('../boob', params={'next': '..'},
                                      append={'next': 'yy'}),
                             '../boob?next=..&next=yy')
        self.assertEqualsURL(make_url('auth_login', params={'next': '/zob'}),
                             '/login/?next=%2Fzob')
        self.assertEqualsURL(make_url('auth_login', params={'next': '/zob'},
                                      fragment='a2-panel'),
                             '/login/?next=%2Fzob#a2-panel')

    def test_redirect(self):
        from authentic2.utils import redirect
        from django.test.client import RequestFactory
        rf = RequestFactory()
        request = rf.get('/coin', data={'next': '..'})
        request2 = rf.get('/coin', data={'next': '..', 'token': 'xxx'})
        response = redirect(request, '/boob/', keep_params=True)
        self.assertEqualsURL(response['Location'], '/boob/?next=..')
        response = redirect(request, '/boob/', keep_params=True,
                            exclude=['next'])
        self.assertEqualsURL(response['Location'], '/boob/')
        response = redirect(request2, '/boob/', keep_params=True)
        self.assertEqualsURL(response['Location'], '/boob/?token=xxx&next=..')
        response = redirect(request, '/boob/', keep_params=True,
                            exclude=['token'])
        self.assertEqualsURL(response['Location'], '/boob/?next=..')
        response = redirect(request, '/boob/', keep_params=True,
                            include=['next'])
        self.assertEqualsURL(response['Location'], '/boob/?next=..')
        response = redirect(request, '/boob/', keep_params=True,
                            include=['next'], params={'token': 'uuu'})
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
        self.assertEqualsURL(
            urlparse.parse_qs(
                response['Location'].split('?', 1)[1])['next'][0],
            '/coin?nonce=xxx&next=/zob/')


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


class UserProfileTests(TestCase):
    def setUp(self):
        User = get_user_model()
        user = User.objects.create(username='testbot')
        user.set_password('secret')
        user.save()
        self.client = Client()

    def test_edit_profile_attributes(self):
        # disable existing attributes
        models.Attribute.objects.update(disabled=True)

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
        self.assertTrue(self.client.login(username='testbot',
                                          password='secret'))

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
        # disable existing attributes
        models.Attribute.objects.update(disabled=True)

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

        self.assertTrue(self.client.login(username='testbot',
                                          password='secret'))
        response = self.client.get(reverse('profile_edit'))
        form = get_response_form(response)
        self.assertEqual(set(form.fields), set())


class CacheTests(TestCase):
    urls = 'cache_urls'

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

        def f2(a, b):
            return a
        # few chances the same value comme two times in a row
        self.assertNotEquals(f(), f())

        # with cache the same value will come back
        g = GlobalCache(f, hostname_vary=False)
        values = set()
        for x in range(10):
            values.add(g())
        self.assertEquals(len(values), 1)
        # with and hostname vary 10 values will come back
        g = GlobalCache(f, hostname_vary=True)
        values = set()
        for x in range(10):
            values.add(g())
        self.assertEquals(len(values), 10)
        # null timeout, no cache
        h = GlobalCache(timeout=0)(f)
        self.assertNotEquals(h(), h())
        # vary on second arg
        i = GlobalCache(hostname_vary=False, args=(1,))(f2)
        for a in range(1, 10):
            self.assertEquals(i(a, 1), 1)
        for a in range(2, 10):
            self.assertEquals(i(a, a), a)

    def test_django_cache(self):
        response1 = self.client.get('/django_cache/',
                                    HTTP_HOST='cache1.example.com')
        response2 = self.client.get('/django_cache/',
                                    HTTP_HOST='cache2.example.com')
        response3 = self.client.get('/django_cache/',
                                    HTTP_HOST='cache1.example.com')
        self.assertNotEqual(response1.content, response2.content)
        self.assertEqual(response1.content, response3.content)

    def test_session_cache(self):
        client = Client()
        response1 = client.get('/session_cache/')
        response2 = client.get('/session_cache/')
        client = Client()
        response3 = client.get('/session_cache/')
        self.assertEqual(response1.content, response2.content)
        self.assertNotEqual(response1.content, response3.content)


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
            self.assertTrue(
                isinstance(attribute_kinds.get_form_field('string'),
                           forms.CharField))
            self.assertEqual(
                attribute_kinds.get_kind('string')['name'], 'string')
            self.assertTrue(
                isinstance(attribute_kinds.get_form_field('integer'),
                           forms.IntegerField))
            self.assertEqual(
                attribute_kinds.get_kind('integer')['name'],
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


class APITest(TestCase):
    def setUp(self):
        User = get_user_model()
        Role = get_role_model()
        OU = get_ou_model()

        ct_user = ContentType.objects.get_for_model(User)

        self.ou = OU.objects.create(slug='ou', name='OU', email_is_unique=True,
                                    username_is_unique=True)
        self.reguser1 = User.objects.create(username='reguser1')
        self.reguser1.set_password('password')
        self.reguser1.save()
        cred = '%s:%s' % (self.reguser1.username.encode('utf-8'), 'password')
        self.reguser1_cred = base64.b64encode(cred)
        self.user_admin_role = Role.objects.get_admin_role(
            instance=ct_user, name='user admin', slug='user-admin')
        self.reguser1.roles.add(self.user_admin_role)

        self.reguser2 = User.objects.create(username='reguser2',
                                            password='password')
        self.reguser2.set_password('password')
        self.reguser2.save()
        cred = '%s:%s' % (self.reguser2.username.encode('utf-8'), 'password')
        self.reguser2_cred = base64.b64encode(cred)
        self.ou_user_admin_role = Role.objects.get_admin_role(
            instance=ct_user, name='user admin', slug='user-admin',
            ou=self.ou)
        self.ou_user_admin_role.members.add(self.reguser2)

        self.reguser3 = User.objects.create(username='reguser3',
                                            password='password',
                                            is_superuser=True)
        self.reguser3.set_password('password')
        self.reguser3.save()
        cred = '%s:%s' % (self.reguser3.username.encode('utf-8'), 'password')
        self.reguser3_cred = base64.b64encode(cred)

    def test_register_reguser1(self):
        self.register_with_user(self.reguser1, self.reguser1_cred)

    def test_register_reguser2(self):
        self.register_with_user(self.reguser2, self.reguser2_cred)

    def test_register_reguser3(self):
        self.register_with_user(self.reguser3, self.reguser3_cred)

    @override_settings(A2_REQUIRED_FIELDS=['username'])
    def register_with_user(self, user, cred):
        from django.contrib.auth import get_user_model
        from rest_framework import test
        from rest_framework import status

        # disable existing attributes
        models.Attribute.objects.update(disabled=True)

        User = get_user_model()
        user_count = User.objects.count()
        client = test.APIClient()
        password = '12=XY=ab'
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
        client.credentials(HTTP_AUTHORIZATION='Basic %s' % cred)
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('result', response.data)
        self.assertEqual(response.data['result'], 1)
        self.assertIn('token', response.data)
        token = response.data['token']
        self.assertEqual(len(mail.outbox), outbox_level + 1)

        # User side
        client = Client()
        activation_mail = mail.outbox[-1]
        m = re.search('https?://[^\n ]*', activation_mail.body)
        self.assertNotEqual(m, None)
        activation_url = m.group()
        response = client.get(activation_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert utils.make_url(return_url, params={'token': token}) in response.content
        self.assertEqual(User.objects.count(), user_count + 1)
        response = client.get(reverse('auth_homepage'))
        self.assertContains(response, username)
        last_user = User.objects.order_by('id').last()
        self.assertEqual(last_user.username, username)
        self.assertEqual(last_user.email, email)
        self.assertEqual(last_user.ou.slug, self.ou.slug)
        self.assertTrue(last_user.check_password(password))

        # Test email is unique with case change
        client = test.APIClient()
        client.credentials(HTTP_AUTHORIZATION='Basic %s' % cred)
        payload = {
            'email': email.upper(),
            'username': username + '1',
            'ou': self.ou.slug,
            'password': password,
            'return_url': return_url,
        }
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.data['errors']['__all__'],
                         [_('You already have an account')])
        # Username is required
        payload = {
            'email': '1' + email,
            'ou': self.ou.slug,
            'password': password,
            'return_url': return_url,
        }
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.data['errors']['__all__'],
                         [_('Username is required in this ou')])
        # Test username is unique
        payload = {
            'email': '1' + email,
            'username': username,
            'ou': self.ou.slug,
            'password': password,
            'return_url': return_url,
        }
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.data['errors']['__all__'],
                         [_('You already have an account')])

    def test_register_reguser2_wrong_ou(self):
        client = test.APIClient()
        password = '12=XY=ab'
        username = 'john.doe'
        email = 'john.doe@example.com'
        return_url = 'http://sp.org/register/'
        payload = {
            'email': email,
            'username': username,
            'ou': 'default',
            'password': password,
            'return_url': return_url,
        }
        client.credentials(HTTP_AUTHORIZATION='Basic %s' % self.reguser2_cred)
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEquals(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('errors', response.data)

    @override_settings(A2_REQUIRED_FIELDS=['username'])
    def test_email_is_unique_double_registration(self):
        from django.contrib.auth import get_user_model
        from rest_framework import test
        from rest_framework import status

        # disable existing attributes
        models.Attribute.objects.update(disabled=True)

        user = self.reguser3
        cred = self.reguser3_cred
        User = get_user_model()
        user_count = User.objects.count()
        client = test.APIClient()
        password = '12=XY=ab'
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
        client.credentials(HTTP_AUTHORIZATION='Basic %s' % cred)
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('result', response.data)
        self.assertEqual(response.data['result'], 1)
        self.assertIn('token', response.data)
        token = response.data['token']
        self.assertEqual(len(mail.outbox), outbox_level + 1)
        outbox_level = len(mail.outbox)

        # Second registration
        response2 = client.post(reverse('a2-api-register'),
                                content_type='application/json',
                                data=json.dumps(payload))
        self.assertEqual(response2.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('result', response2.data)
        self.assertEqual(response2.data['result'], 1)
        self.assertIn('token', response2.data)
        token2 = response2.data['token']
        self.assertEqual(len(mail.outbox), outbox_level + 1)

        # User side - user click on first email
        client = Client()
        activation_mail = mail.outbox[-2]
        m = re.search('https?://[^\n ]*', activation_mail.body)
        self.assertNotEqual(m, None)
        activation_url = m.group()
        response = client.get(activation_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert utils.make_url(return_url, params={'token': token}) in response.content
        self.assertEqual(User.objects.count(), user_count + 1)
        response = client.get(reverse('auth_homepage'))
        self.assertContains(response, username)
        last_user = User.objects.order_by('id').last()
        self.assertEqual(last_user.username, username)
        self.assertEqual(last_user.email, email)
        self.assertEqual(last_user.ou.slug, self.ou.slug)
        self.assertTrue(last_user.check_password(password))

        # User click on second email
        client = Client()
        activation_mail = mail.outbox[-1]
        m = re.search('https?://[^\n ]*', activation_mail.body)
        self.assertNotEqual(m, None)
        activation_url = m.group()
        response = client.get(activation_url)
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertEqual(response['Location'],
                         utils.make_url(return_url, params={'token': token2}))
        self.assertEqual(User.objects.count(), user_count + 1)
        response = client.get(reverse('auth_homepage'))
        self.assertContains(response, username)
        last_user2 = User.objects.order_by('id').last()
        self.assertEqual(User.objects.filter(email=payload['email']).count(), 1)
        self.assertEqual(last_user.id, last_user2.id)
        self.assertEqual(last_user2.username, username)
        self.assertEqual(last_user2.email, email)
        self.assertEqual(last_user2.ou.slug, self.ou.slug)
        self.assertTrue(last_user2.check_password(password))

        # Test email is unique with case change
        client = test.APIClient()
        client.credentials(HTTP_AUTHORIZATION='Basic %s' % cred)
        payload = {
            'email': email.upper(),
            'username': username + '1',
            'ou': self.ou.slug,
            'password': password,
            'return_url': return_url,
        }
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.data['errors']['__all__'],
                         [_('You already have an account')])
        # Username is required
        payload = {
            'email': '1' + email,
            'ou': self.ou.slug,
            'password': password,
            'return_url': return_url,
        }
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.data['errors']['__all__'],
                         [_('Username is required in this ou')])
        # Test username is unique
        payload = {
            'email': '1' + email,
            'username': username,
            'ou': self.ou.slug,
            'password': password,
            'return_url': return_url,
        }
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.data['errors']['__all__'],
                         [_('You already have an account')])

    @override_settings(A2_REQUIRED_FIELDS=['username'])
    def test_email_username_is_unique_double_registration(self):
        from django.contrib.auth import get_user_model
        from rest_framework import test
        from rest_framework import status

        # disable existing attributes
        models.Attribute.objects.update(disabled=True)

        cred = self.reguser3_cred
        User = get_user_model()
        user_count = User.objects.count()
        client = test.APIClient()
        password = '12=XY=ab'
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
        client.credentials(HTTP_AUTHORIZATION='Basic %s' % cred)
        response = client.post(reverse('a2-api-register'),
                               content_type='application/json',
                               data=json.dumps(payload))
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('result', response.data)
        self.assertEqual(response.data['result'], 1)
        self.assertIn('token', response.data)
        token = response.data['token']
        self.assertEqual(len(mail.outbox), outbox_level + 1)
        outbox_level = len(mail.outbox)

        # Second registration
        payload['email'] = 'john.doe2@example.com'
        response2 = client.post(reverse('a2-api-register'),
                                content_type='application/json',
                                data=json.dumps(payload))
        self.assertEqual(response2.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('result', response2.data)
        self.assertEqual(response2.data['result'], 1)
        self.assertIn('token', response2.data)
        self.assertEqual(len(mail.outbox), outbox_level + 1)

        # User side - user click on first email
        client = Client()
        activation_mail = mail.outbox[-2]
        m = re.search('https?://[^\n ]*', activation_mail.body)
        self.assertNotEqual(m, None)
        activation_url = m.group()
        response = client.get(activation_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert utils.make_url(return_url, params={'token': token}) in response.content
        self.assertEqual(User.objects.count(), user_count + 1)
        response = client.get(reverse('auth_homepage'))
        self.assertContains(response, username)
        last_user = User.objects.order_by('id').last()
        self.assertEqual(last_user.username, username)
        self.assertEqual(last_user.email, email)
        self.assertEqual(last_user.ou.slug, self.ou.slug)
        self.assertTrue(last_user.check_password(password))

        # User click on second email
        client = Client()
        activation_mail = mail.outbox[-1]
        m = re.search('https?://[^\n ]*', activation_mail.body)
        self.assertNotEqual(m, None)
        activation_url = m.group()
        response = client.get(activation_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response, 'form', 'username',
            _('This username is already in use. Please supply a different username.'))
