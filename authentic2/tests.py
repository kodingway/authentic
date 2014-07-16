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

