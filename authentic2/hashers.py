import hashlib
import math
import base64

from django.contrib.auth import hashers
from django.utils.crypto import constant_time_compare
from django.utils.datastructures import SortedDict
from django.utils.translation import ugettext_noop as _
from django.utils.encoding import force_bytes
from django.contrib.auth.hashers import make_password


class Drupal7PasswordHasher(hashers.BasePasswordHasher):
    """
    Secure password hashing using the algorithm used by Drupal 7 (recommended)
    """
    algorithm = "drupal7_sha512"
    iterations = 10000
    digest = hashlib.sha512
    alphabet = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    def atoi64(self, v):
        return self.alphabet.find(v)

    def i64toa(self, v):
        return self.alphabet[v]

    def b64encode(self, v):
        out = ''
        count = len(v)
        i = 0
        while i < count:
            value = ord(v[i])
            i += 1
            out += self.i64toa(value & 0x3f)
            if i < count:
                value |= ord(v[i]) << 8
            out += self.i64toa((value >> 6) & 0x3f)
            if i == count:
                break
            i += 1
            if i < count:
                value |= ord(v[i]) << 16
            out += self.i64toa((value >> 12) & 0x3f)
            if i == count:
                break
            i += 1
            out += self.i64toa((value >> 18) & 0x3f)
        return out

    def from_drupal(self, encoded):
        ident, log_count, salt, h = encoded[:3], encoded[3], encoded[4:12], encoded[12:]
        if ident != '$S$':
            raise ValueError('Not a Drupal7 SHA-512 hashed password')
        count = 1 << self.atoi64(log_count)
        return '%s$%s$%s$%s' % (self.algorithm, count, salt, h)

    def to_drupal(self, encoded):
        algo, count, salt, h = encoded.split('$', 3)
        count = self.atoi64(math.ceil(math.log(count, 2)))
        return '$S$%s%s%s' % (count, salt, h)

    def encode(self, password, salt, iterations):
        assert password
        assert salt and '$' not in salt
        h = salt
        password = force_bytes(password)
        for i in xrange(iterations+1):
            h = self.digest(h + password).digest()
        return "%s$%d$%s$%s" % (self.algorithm, iterations, salt, self.b64encode(h)[:43])

    def verify(self, password, encoded):
        algorithm, iterations, salt, hash = encoded.split('$', 3)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt, int(iterations))
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        algorithm, iterations, salt, hash = encoded.split('$', 3)
        assert algorithm == self.algorithm
        return SortedDict([
            (_('algorithm'), algorithm),
            (_('iterations'), iterations),
            (_('salt'), hashers.mask_hash(salt)),
            (_('hash'), hashers.mask_hash(hash)),
        ])


class CommonPasswordHasher(hashers.BasePasswordHasher):
    """
    The Salted MD5 password hashing algorithm (not recommended)
    """
    algorithm = None
    digest = None

    def encode(self, password, salt):
        assert password
        assert '$' not in salt
        hash = self.digest(force_bytes(salt + password)).hexdigest()
        return "%s$%s$%s" % (self.algorithm, salt, hash)

    def verify(self, password, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt)
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        assert algorithm == self.algorithm
        return SortedDict([
            (_('algorithm'), algorithm),
            (_('salt'), hashers.mask_hash(salt, show=2)),
            (_('hash'), hashers.mask_hash(hash)),
        ])


OPENLDAP_ALGO_MAPPING = {
         #        hasher? salt offset?  hex encode?
        'SHA':   ( 'sha-oldap',  0,  True),
        'SSHA':  ('ssha-oldap', 20,  True),
        'MD5':   ( 'md5-oldap',  0,  True),
        'SMD5':  ( 'md5-oldap', 16,  True),
}


def olap_password_to_dj(password):
    '''Convert an LDAP password for Django use eventually hashed'''
    if password[0] == '{' and '}' in password:
        algo = password[1:].split('}')[0]
        if algo not in OPENLDAP_ALGO_MAPPING:
            raise ValueError('unknown algorithm %r' % algo)
        password = password[1:].split('}')[1]
        try:
            password = base64.b64decode(password)
        except ValueError:
            raise ValueError('unable to decode base64 hash %r' % password)
        algo_name, salt_offset, hex_encode = OPENLDAP_ALGO_MAPPING[algo]
        salt, password = (password[salt_offset:], password[:salt_offset]) if salt_offset else ('', password)
        if hex_encode:
            password = password.encode('hex')
        return '%s$%s$%s' % (algo_name, salt.encode('hex'), password)
    else:
        return make_password(password)


class OpenLDAPPasswordHasher(CommonPasswordHasher):
    def encode(self, password, salt):
        assert password
        assert '$' not in salt
        hash = self.digest(force_bytes(password + salt)).hexdigest()
        return "%s$%s$%s" % (self.algorithm, salt.encode('hex'), hash)

    def verify(self, password, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        hash = hash.decode('hex')
        salt = salt.decode('hex')
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt)
        return constant_time_compare(encoded, encoded_2)


class SHA256PasswordHasher(CommonPasswordHasher):
    algorithm = 'sha256'
    digest = hashlib.sha256


class SSHA1PasswordHasher(OpenLDAPPasswordHasher):
    algorithm = 'ssha-oldap'
    digest = hashlib.sha1


class SMD5PasswordHasher(OpenLDAPPasswordHasher):
    algorithm = 'smd5-oldap'
    digest = hashlib.md5

class SHA1OLDAPPasswordHasher(OpenLDAPPasswordHasher):
    algorithm = 'sha-oldap'
    digest = hashlib.sha1

    def salt(self):
        return ''

class MD5OLDAPPasswordHasher(OpenLDAPPasswordHasher):
    algorithm = 'md5-oldap'
    digest = hashlib.md5

    def salt(self):
        return ''
