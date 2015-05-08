import os
if 'DB' in os.environ:
    DATABASES = {
        'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ['DB'],
        }
    }
DEBUG=True
# DEBUG_DB=True
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
# A2_IDP_SAML2_ENABLE = True
# A2_EMAIL_IS_UNIQUE = True
INSTALLED_APPS += ('debug_toolbar',)
A2_PASSWORD_POLICY_MIN_CLASSES = 0
A2_PASSWORD_POLICY_MIN_LENGTH = 0
A2_IDP_CAS_ENABLE = True
A2_IDP_SAML_ENABLE = True
