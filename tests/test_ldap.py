# -*- coding: utf-8 -*-
import pytest

from authentic2_provisionning_ldap.ldap_utils import Slapd, has_slapd
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from authentic2.a2_rbac.utils import get_default_ou
from django_rbac.utils import get_ou_model

pytestmark = pytest.mark.skipunless(has_slapd(), reason='slapd is not installed')

slapd = None


def setup_module(module):
    global slapd
    slapd = Slapd()
    slapd.add_ldif('''dn: uid=etienne.michu,o=orga
objectClass: inetOrgPerson
userPassword: pass
uid: etienne.michu
cn: Étienne Michu
sn: Michu
gn: Étienne
mail: etienne.michu@example.net''')


def teardown_module(module):
    slapd.clean()


def setup_function(function):
    slapd.checkpoint()


def teardown_function(function):
    slapd.restore()


def test_connection():
    conn = slapd.get_connection()
    conn.simple_bind_s('uid=etienne.michu,o=orga', 'pass')


@pytest.mark.django_db
def test_simple(settings, client):
    settings.LDAP_AUTH_SETTINGS = [{
        'url': [slapd.ldapi_url],
        'basedn': 'o=orga',
        'use_tls': False,
    }]
    result = client.post('/login/', {'login-password-submit': '1',
                                     'username': 'etienne.michu',
                                     'password': 'pass'}, follow=True)
    assert result.status_code == 200
    assert 'Étienne Michu' in str(result)
    User = get_user_model()
    assert User.objects.count() == 1
    user = User.objects.get()
    assert user.username == 'etienne.michu@ldap'
    assert user.first_name == u'Étienne'
    assert user.last_name == 'Michu'
    assert user.ou == get_default_ou()
    assert not user.check_password('pass')


@pytest.mark.django_db
def test_custom_ou(settings, client):
    OU = get_ou_model()
    ou = OU.objects.create(name='test', slug='test')
    settings.LDAP_AUTH_SETTINGS = [{
        'url': [slapd.ldapi_url],
        'basedn': 'o=orga',
        'use_tls': False,
        'ou_slug': 'test',
    }]
    result = client.post('/login/', {'login-password-submit': '1',
                                     'username': 'etienne.michu',
                                     'password': 'pass'}, follow=True)
    assert result.status_code == 200
    assert 'Étienne Michu' in str(result)
    User = get_user_model()
    assert User.objects.count() == 1
    user = User.objects.get()
    assert user.username == u'etienne.michu@ldap'
    assert user.first_name == u'Étienne'
    assert user.last_name == u'Michu'
    assert user.ou == ou
    assert not user.check_password('pass')


@pytest.mark.django_db
def test_wrong_ou(settings, client):
    settings.LDAP_AUTH_SETTINGS = [{
        'url': [slapd.ldapi_url],
        'basedn': 'o=orga',
        'use_tls': False,
        'ou_slug': 'test',
    }]
    with pytest.raises(ImproperlyConfigured):
        result = client.post('/login/', {'login-password-submit': '1',
                                         'username': 'etienne.michu',
                                         'password': 'pass'}, follow=True)
