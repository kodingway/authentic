import random
import uuid
import time

import pytest
from authentic2 import crypto

key = '1234'


def test_idempotency():
    for i in range(10):
        s = str(random.getrandbits(1024))
        assert crypto.aes_base64_decrypt(key, crypto.aes_base64_encrypt(key, s)) == s


def test_exceptions():
    with pytest.raises(crypto.DecryptionError):
        crypto.aes_base64_decrypt(key, 'xxxx')
    with pytest.raises(crypto.DecryptionError):
        crypto.aes_base64_decrypt(key, 'xxx$y')
    assert crypto.aes_base64_decrypt(key, 'xxxx', raise_on_error=False) is None
    assert crypto.aes_base64_decrypt(key, 'xxx$y', raise_on_error=False) is None


def test_padding():
    from Crypto import Random

    for i in range(1, 100):
        for j in range(2, 32):
            msg = Random.get_random_bytes(i)
            assert crypto.remove_padding(crypto.add_padding(msg, j)) == msg


def test_deterministic_encryption():
    salt = '4567'
    raw = uuid.uuid4().bytes

    for hash_name in ['md5', 'sha1', 'sha256', 'sha384', 'sha512']:
        for count in [0, 1, 50]:
            crypted1 = crypto.aes_base64url_deterministic_encrypt(key, raw, salt,
                                                                  hash_name=hash_name, count=count)
            crypted2 = crypto.aes_base64url_deterministic_encrypt(key, raw, salt,
                                                                  hash_name=hash_name, count=count)
            assert crypted1 == crypted2
            print 'Crypted', hash_name, count, len(crypted1), crypted1

            t = time.time()
            for i in range(100):
                crypted1 = crypto.aes_base64url_deterministic_encrypt(key, raw, salt,
                                                                      hash_name=hash_name,
                                                                      count=count)
            print 'Encryption time:', hash_name, count, (time.time() - t) / 100.0

            t = time.time()
            for i in range(1000):
                assert crypto.aes_base64url_deterministic_decrypt(key, crypted1, salt,
                                                                  max_count=count) == raw
            print 'Decryption time:', hash_name, count, (time.time() - t) / 1000.0
