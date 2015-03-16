import ldap

from django.test import TestCase
from unittest import skipUnless

from authentic2_provisionning_ldap.ldap_utils import Slapd, has_slapd
from django.core.management import call_command
from authentic2 import compat


@skipUnless(has_slapd(), 'slapd is not installed')
class LDAPBaseTestCase(TestCase):
    slapd = None

    def setUp(self):
        if self.slapd is None:
            self.slapd = Slapd()
        self.slapd.checkpoint()
        # fresh connection
        self.conn = self.slapd.get_connection()

    def tearDown(self):
        self.slapd.restore()

class WhoamiTest(LDAPBaseTestCase):
    def test_whoami(self):
        self.conn.simple_bind_s('uid=admin,o=orga', 'admin')
        assert self.conn.whoami_s() == 'dn:uid=admin,o=orga'

class ProvisionTest(LDAPBaseTestCase):
    def test_ldap_provisionning(self):
        ressources = [{
            'name': 'ldap',
            'url': self.slapd.ldapi_url,
            'bind_dn': 'uid=admin,o=orga',
            'bind_pw': 'admin',
            'base_dn': 'o=orga',
            'rdn_attributes': ['uid',],
            'attribute_mapping': {
                'uid': 'django_user_username',
                'givenName': 'django_user_first_name',
                'sn': 'django_user_last_name',
                'mail': 'django_user_email',
            },
            'format_mapping': {
                'cn': ['{django_user_first_name} {django_user_last_name}'],
            },
            'static_attributes': {
                'objectclass': 'inetorgperson',
            },
            'ldap_filter': '(objectclass=inetorgperson)',
        }]
        User = compat.get_user_model()
        users = [User(username='john.doe%s' % i,
                first_name='john',
                last_name='doe',
                email='john.doe@example.com') for i in range(1000)]

        User.objects.bulk_create(users)
        self.slapd.add_ldif('''dn: uid=test,o=orga
objectClass: inetOrgPerson
uid: test
cn: test
sn: test
gn: test
mail: test''')
        with self.settings(A2_PROVISIONNING_RESSOURCES=ressources):
            call_command('provision', 'ldap', batch_size=1000)
        results = self.conn.search_s('o=orga', ldap.SCOPE_ONELEVEL)
        self.assertEqual(len(results), 1000)
        for dn, entry in results:
            uid = entry['uid'][0]
            self.assertTrue(uid.startswith('john.doe'))
            self.assertEquals(entry, {
                        'objectClass': ['inetOrgPerson'],
                        'uid': [uid],
                        'sn': [users[0].last_name],
                        'givenName': [users[0].first_name],
                        'cn': ['%s %s' % (users[0].first_name, users[0].last_name)],
                        'mail': [users[0].email]
            })
