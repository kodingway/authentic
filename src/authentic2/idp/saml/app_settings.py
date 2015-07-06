class AppSettings(object):
    __DEFAULTS = dict(
            ENABLE=False,
            METADATA_OPTIONS={},
            SECONDS_TOLERANCE=60,
            AUTHN_CONTEXT_FROM_SESSION=True,
            SIGNATURE_PUBLIC_KEY = '''-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIJANUBoick1pDpMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNV
BAoTCkVudHJvdXZlcnQwHhcNMTAxMjE0MTUzMzAyWhcNMTEwMTEzMTUzMzAyWjAV
MRMwEQYDVQQKEwpFbnRyb3V2ZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAvxFkfPdndlGgQPDZgFGXbrNAc/79PULZBuNdWFHDD9P5hNhZn9Kqm4Cp
06Pe/A6u+g5wLnYvbZQcFCgfQAEzziJtb3J55OOlB7iMEI/T2AX2WzrUH8QT8NGh
ABONKU2Gg4XiyeXNhH5R7zdHlUwcWq3ZwNbtbY0TVc+n665EbrfV/59xihSqsoFr
kmBLH0CoepUXtAzA7WDYn8AzusIuMx3n8844pJwgxhTB7Gjuboptlz9Hri8JRdXi
VT9OS9Wt69ubcNoM6zuKASmtm48UuGnhj8v6XwvbjKZrL9kA+xf8ziazZfvvw/VG
Tm+IVFYB7d1x457jY5zjjXJvNysoowIDAQABo3YwdDAdBgNVHQ4EFgQUeF8ePnu0
fcAK50iBQDgAhHkOu8kwRQYDVR0jBD4wPIAUeF8ePnu0fcAK50iBQDgAhHkOu8mh
GaQXMBUxEzARBgNVBAoTCkVudHJvdXZlcnSCCQDVAaInJNaQ6TAMBgNVHRMEBTAD
AQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAy8l3GhUtpPHx0FxzbRHVaaUSgMwYKGPhE
IdGhqekKUJIx8et4xpEMFBl5XQjBNq/mp5vO3SPb2h2PVSks7xWnG3cvEkqJSOeo
fEEhkqnM45b2MH1S5uxp4i8UilPG6kmQiXU2rEUBdRk9xnRWos7epVivTSIv1Ncp
lG6l41SXp6YgIb2ToT+rOKdIGIQuGDlzeR88fDxWEU0vEujZv/v1PE1YOV0xKjTT
JumlBc6IViKhJeo1wiBBrVRIIkKKevHKQzteK8pWm9CYWculxT26TZ4VWzGbo06j
o2zbumirrLLqnt1gmBDvDvlOwC/zAAyL4chbz66eQHTiIYZZvYgy
-----END CERTIFICATE-----''',
            SIGNATURE_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvxFkfPdndlGgQPDZgFGXbrNAc/79PULZBuNdWFHDD9P5hNhZ
n9Kqm4Cp06Pe/A6u+g5wLnYvbZQcFCgfQAEzziJtb3J55OOlB7iMEI/T2AX2WzrU
H8QT8NGhABONKU2Gg4XiyeXNhH5R7zdHlUwcWq3ZwNbtbY0TVc+n665EbrfV/59x
ihSqsoFrkmBLH0CoepUXtAzA7WDYn8AzusIuMx3n8844pJwgxhTB7Gjuboptlz9H
ri8JRdXiVT9OS9Wt69ubcNoM6zuKASmtm48UuGnhj8v6XwvbjKZrL9kA+xf8ziaz
Zfvvw/VGTm+IVFYB7d1x457jY5zjjXJvNysoowIDAQABAoIBAQCj8t2iKXya10HG
V6Saaeih8aftoLBV38VwFqqjPU0+iKqDpk2JSXBhjI6s7uFIsaTNJpR2Ga1qvns1
hJQEDMQSLhJvXfBgSkHylRWCpJentr4E3D7mnw5pRsd61Ev9U+uHcdv/WHP4K5hM
xsdiwXNXD/RYd1Q1+6bKrCuvnNJVmWe0/RV+r3T8Ni5xdMVFbRWt/VEoE620XX6c
a9TQPiA5i/LRVyie+js7Yv+hVjGOlArtuLs6ECQsivfPrqKLOBRWcofKdcf+4N2e
3cieUqwzC15C31vcMliD9Hax9c1iuTt9Q3Xzo20fOSazAnQ5YBEExyTtrFBwbfQu
ku6hp81pAoGBAN6bc6iJtk5ipYpsaY4ZlbqdjjG9KEXB6G1MExPU7SHXOhOF0cDH
/pgMsv9hF2my863MowsOj3OryVhdQhwA6RrV263LRh+JU8NyHV71BwAIfI0BuVfj
6r24KudwtUcvMr9pJIrJyMAMaw5ZyNoX7YqFpS6fcisSJYdSBSoxzrzVAoGBANu6
xVeMqGavA/EHSOQP3ipDZ3mnWbkDUDxpNhgJG8Q6lZiwKwLoSceJ8z0PNY3VetGA
RbqtqBGfR2mcxHyzeqVBpLnXZC4vs/Vy7lrzTiHDRZk2SG5EkHMSKFA53jN6S/nJ
JWpYZC8lG8w4OHaUfDHFWbptxdGYCgY4//sjeiuXAoGBANuhurJ99R5PnA8AOgEW
4zD1hLc0b4ir8fvshCIcAj9SUB20+afgayRv2ye3Dted1WkUL4WYPxccVhLWKITi
rRtqB03o8m3pG3kJnUr0LIzu0px5J/o8iH3ZOJOTE3iBa+uI/KHmxygc2H+XPGFa
HGeAxuJCNO2kAN0Losbnz5dlAoGAVsCn94gGWPxSjxA0PC7zpTYVnZdwOjbPr/pO
LDE0cEY9GBq98JjrwEd77KibmVMm+Z4uaaT0jXiYhl8pyJ5IFwUS13juCbo1z/u/
ldMoDvZ8/R/MexTA/1204u/mBecMJiO/jPw3GdIJ5phv2omHe1MSuSNsDfN8Sbap
gmsgaiMCgYB/nrTk89Fp7050VKCNnIt1mHAcO9cBwDV8qrJ5O3rIVmrg1T6vn0aY
wRiVcNacaP+BivkrMjr4BlsUM6yH4MOBsNhLURiiCL+tLJV7U0DWlCse/doWij4U
TKX6tp6oI+7MIJE6ySZ0cBqOiydAkBePZhu57j6ToBkTa0dbHjn1WA==
-----END RSA PRIVATE KEY-----''',
            ADD_CERTIFICATE_TO_KEY_INFO=True,
    )

    def __init__(self, prefix):
        self.prefix = prefix

    def _setting(self, name, dflt):
        from django.conf import settings
        return getattr(settings, name, dflt)

    def _setting_with_prefix(self, name, dflt):
        return self._setting(self.prefix + name, dflt)

    @property
    def ENABLE(self):
        return self._setting_with_prefix('ENABLE',
                   self._setting('IDP_SAML2',
                       self.__DEFAULTS['ENABLE']))

    @property
    def SIGNATURE_PUBLIC_KEY(self):
        return self._setting_with_prefix('SIGNATURE_PUBLIC_KEY',
                   self._setting('SAML_SIGNATURE_PUBLIC_KEY',
                       self.__DEFAULTS['SIGNATURE_PUBLIC_KEY']))

    @property
    def SIGNATURE_PRIVATE_KEY(self):
        return self._setting_with_prefix('SIGNATURE_PRIVATE_KEY',
                   self._setting('SAML_SIGNATURE_PRIVATE_KEY',
                       self.__DEFAULTS['SIGNATURE_PRIVATE_KEY']))

    @property
    def AUTHN_CONTEXT_FROM_SESSION(self):
        return self._setting_with_prefix('AUTHN_CONTEXT_FROM_SESSION',
                   self._setting('IDP_SAML2_AUTHN_CONTEXT_FROM_SESSION',
                       self.__DEFAULTS['AUTHN_CONTEXT_FROM_SESSION']))

    def is_default(self, name):
        return getattr(self, name) == self.__DEFAULTS[name]

    def __getattr__(self, name):
        if name not in self.__DEFAULTS:
            raise AttributeError(name)
        return self._setting_with_prefix(name, self.__DEFAULTS[name])


# Ugly? Guido recommends this himself ...
# http://mail.python.org/pipermail/python-ideas/2012-May/014969.html
import sys
app_settings = AppSettings('A2_IDP_SAML2_')
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
