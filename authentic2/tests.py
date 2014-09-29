from django.test import TestCase

from django.contrib.auth.hashers import check_password

from . import hashers

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
        s.serialize([u, a, av], use_natural_keys=True)
        result = s.getvalue()
        u.delete()
        a.delete()
        self.assertEqual(User.objects.count(), 0)
        self.assertEqual(Attribute.objects.count(), 0)
        self.assertEqual(AttributeValue.objects.count(), 0)
        expected = [ {'pk': ['john.doe'],
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
                  {'pk': ['phone'],
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
                 {'pk': [['auth', 'user'], ['john.doe'], ['phone']],
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
