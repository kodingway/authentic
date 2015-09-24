import pytest

from authentic2_provisionning_ldap.ldap_utils import Slapd, has_slapd

pytestmark = pytest.mark.skipunless(has_slapd(), reason='slapd is not installed')

slapd = None

def setup_module(module):
    global slapd
    slapd = Slapd()
    slapd.add_ldif('''dn: uid=test,o=orga
objectClass: inetOrgPerson
userPassword: test
uid: test
cn: test
sn: test
gn: test
mail: test''')

def teardown_module(module):
    slapd.clean()

def setup_function(function):
    slapd.checkpoint()

def teardown_function(function):
    slapd.restore()

def test_connection():
    conn = slapd.get_connection()
    conn.simple_bind_s('uid=test,o=orga', 'test')

@pytest.mark.django_db
def test_ldap(settings, client):
    settings.LDAP_AUTH_SETTINGS = [{
        'url': [slapd.ldapi_url],
        'basedn': 'o=orga',
        'use_tls': False,
    }]
    result = client.post('/login/', {'login-password-submit': '1',
                                     'username': 'test', 
                                     'password': 'test'}, follow=True)
    assert 'id="user"' in str(result)
    assert 'test test' in str(result)
