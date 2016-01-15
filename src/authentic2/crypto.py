import base64

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random

class DecryptionError(Exception):
    pass

def aes_base64_encrypt(key, data):
    '''Generate an AES key from any key material using PBKDF2, and encrypt data using CFB mode. A
       new IV is generated each time, the IV is also used as salt for PBKDF2.
    '''
    iv = Random.get_random_bytes(16)
    aes_key = PBKDF2(key, iv)
    aes = AES.new(aes_key, AES.MODE_CFB, iv)
    crypted = aes.encrypt(data)
    return '%s$%s' % (base64.b64encode(iv), base64.b64encode(crypted))

def aes_base64_decrypt(key, payload):
    '''Decrypt data encrypted with aes_base64_encrypt'''
    try:
        iv, crypted = payload.split('$')
    except (ValueError, TypeError):
        raise DecryptionError('bad payload')
    try:
        iv = base64.b64decode(iv)
        crypted = base64.b64decode(crypted)
    except TypeError:
        raise DecryptionError('incorrect base64 encoding')
    aes_key = PBKDF2(key, iv)
    aes = AES.new(aes_key, AES.MODE_CFB, iv)
    return aes.decrypt(crypted)
