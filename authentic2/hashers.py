import hashlib
import base64
import math

from django.contrib.auth import hashers
from django.utils.crypto import constant_time_compare
from django.utils.datastructures import SortedDict
from django.utils.translation import ugettext_noop as _

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
