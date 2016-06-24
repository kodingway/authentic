import random

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

