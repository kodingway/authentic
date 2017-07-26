import base64
import hashlib
import struct

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
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


def add_padding(msg, block_size):
    '''Pad message with zero bytes to match block_size'''
    pad_length = block_size - (len(msg) + 2) % block_size
    padded = struct.pack('<h%ds%ds' % (len(msg), pad_length), len(msg), msg, '\0' * pad_length)
    assert len(padded) % block_size == 0
    return padded


def remove_padding(msg, block_size):
    '''Ignore padded zero bytes'''
    try:
        msg_length, = struct.unpack('<h', msg[:2])
    except struct.error:
        raise DecryptionError('wrong padding')
    if len(msg) % block_size != 0:
        raise DecryptionError('message length is not a multiple of block size', len(msg),
                              block_size)
    unpadded = msg[2:2 + msg_length]
    if msg_length > len(msg) - 2:
        raise DecryptionError('wrong padding')
    if not all(c == '\0' for c in msg[2 + msg_length:]):
        raise DecryptionError('padding is not all zero')
    if len(unpadded) != msg_length:
        raise DecryptionError('wrong padding')
    return unpadded


def aes_base64url_deterministic_encrypt(key, data, salt, hash_name='sha256', count=1):
    '''Encrypt using AES-128 and sign using HMAC-SHA256 shortened to 64 bits.

       Count and algorithm are encoded in the final string for future evolution.

    '''
    mode = 1  # AES128-SHA256
    hashmod = SHA256
    key_size = 16
    hmac_size = key_size

    iv = hashmod.new(salt).digest()

    prf = lambda secret, salt: HMAC.new(secret, salt, hashmod).digest()

    aes_key = PBKDF2(key, iv, dkLen=key_size, count=count, prf=prf)

    key_size = len(aes_key)

    aes = AES.new(aes_key, AES.MODE_CBC, iv[:key_size])

    crypted = aes.encrypt(add_padding(data, key_size))

    hmac = prf(key, crypted)[:hmac_size]

    raw = struct.pack('<2sBH', 'a2', mode, count) + crypted + hmac
    return base64url_encode(raw)


def aes_base64url_deterministic_decrypt(key, urlencoded, salt, raise_on_error=True, max_count=1):
    mode = 1  # AES128-SHA256
    hashmod = SHA256
    key_size = 16
    hmac_size = key_size
    prf = lambda secret, salt: HMAC.new(secret, salt, hashmod).digest()

    try:
        try:
            raw = base64url_decode(urlencoded)
        except Exception as e:
            raise DecryptionError('base64 decoding failed', e)
        try:
            magic, mode, count = struct.unpack('<2sBH', raw[:5])
        except struct.error as e:
            raise DecryptionError('invalid packing', e)
        if magic != 'a2':
            raise DecryptionError('invalid magic string', magic)
        if mode != 1:
            raise DecryptionError('mode is not AES128-SHA256', mode)
        if count > max_count:
            raise DecryptionError('count is too big', count)

        crypted, hmac = raw[5:-hmac_size], raw[-hmac_size:]

        if not crypted or not hmac or prf(key, crypted)[:hmac_size] != hmac:
            raise DecryptionError('invalid HMAC')

        iv = hashmod.new(salt).digest()

        aes_key = PBKDF2(key, iv, dkLen=key_size, count=count, prf=prf)

        aes = AES.new(aes_key, AES.MODE_CBC, iv[:key_size])

        data = remove_padding(aes.decrypt(crypted), key_size)

        return data
    except DecryptionError:
        if not raise_on_error:
            return None
        raise
