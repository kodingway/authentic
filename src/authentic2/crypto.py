import base64
import hashlib

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.strxor import strxor
from Crypto import Random


class DecryptionError(Exception):
    pass


def base64url_decode(raw):
    rem = len(raw) % 4
    if rem > 0:
        raw += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(raw)


def base64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip('=')


def get_hashclass(name):
    if name in ['md5', 'sha1', 'sha256', 'sha384', 'sha512']:
        return getattr(hashlib, name)
    return None


def aes_base64_encrypt(key, data):
    '''Generate an AES key from any key material using PBKDF2, and encrypt data using CFB mode. A
       new IV is generated each time, the IV is also used as salt for PBKDF2.
    '''
    iv = Random.get_random_bytes(16)
    aes_key = PBKDF2(key, iv)
    aes = AES.new(aes_key, AES.MODE_CFB, iv)
    crypted = aes.encrypt(data)
    return '%s$%s' % (base64.b64encode(iv), base64.b64encode(crypted))


def aes_base64_decrypt(key, payload, raise_on_error=True):
    '''Decrypt data encrypted with aes_base64_encrypt'''
    try:
        iv, crypted = payload.split('$')
    except (ValueError, TypeError):
        if raise_on_error:
            raise DecryptionError('bad payload')
        return None
    try:
        iv = base64.b64decode(iv)
        crypted = base64.b64decode(crypted)
    except TypeError:
        if raise_on_error:
            raise DecryptionError('incorrect base64 encoding')
        return None
    aes_key = PBKDF2(key, iv)
    aes = AES.new(aes_key, AES.MODE_CFB, iv)
    return aes.decrypt(crypted)


def aes_base64url_deterministic_encrypt(key, data, salt, hash_name='sha256', count=1):
    hashclass = get_hashclass(hash_name)
    if hashclass is None:
        raise ValueError('invalid hash_name')
    iv = hashclass(salt).digest()
    aes_key = PBKDF2(key, iv, count=count)
    key_size = len(aes_key)
    md5 = hashclass(data).digest()[:key_size]
    aes = AES.new(aes_key, AES.MODE_CFB, strxor(iv[:key_size], md5)[:key_size])
    crypted = aes.encrypt(data)
    return '%d$aes-128-%s$%s$%s' % (count, hash_name,
                                    base64url_encode(md5[:key_size]),
                                    base64url_encode(crypted))


def aes_base64url_deterministic_decrypt(key, raw, salt, raise_on_error=True):
    try:
        try:
            splitted = raw.split('$')
        except:
            raise DecryptionError('invalid crypted value', raw)
        if len(splitted) != 4:
            raise DecryptionError('invalid encoding, not enough parts', raw)
        try:
            count = int(splitted[0])
        except ValueError:
            raise DecryptionError('invalid encryption, count is not a number')
        if not splitted[1].startswith('aes-128-'):
            raise DecryptionError('invalid algorithm', splitted[1])
        hashclass = get_hashclass(splitted[1][len('aes-128-'):])
        if hashclass is None:
            raise DecryptionError('invalid hash name', splitted[1])
        try:
            md5 = base64url_decode(splitted[2])
        except TypeError:
            raise DecryptionError('incorrect base64url encoding of hash', splitted[1])
            return None
        try:
            crypted = base64url_decode(splitted[3])
        except TypeError:
            if raise_on_error:
                raise DecryptionError('incorrect base64url encoding of crypted', splitted[2])
            return None
        iv = hashclass(salt).digest()
        aes_key = PBKDF2(key, iv, count=count)
        key_size = len(aes_key)
        if len(md5) != key_size:
            raise DecryptionError('invalid hash length')
        aes = AES.new(aes_key, AES.MODE_CFB, strxor(iv[:key_size], md5)[:len(aes_key)])
        decrypted = aes.decrypt(crypted)
        if hashclass(decrypted).digest()[:key_size] != md5:
            raise DecryptionError('hash does not match decrypted value')
        return decrypted
    except DecryptionError:
        if not raise_on_error:
            return None
        raise
