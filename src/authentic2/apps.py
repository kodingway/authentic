import django
from django.conf import settings
from django.apps import AppConfig
from django.core.checks import register, Warning, Tags

from . import plugins

class Authentic2Config(AppConfig):
    name = 'authentic2'
    verbose_name = 'Authentic2'

    def ready(self):
        plugins.init()

def check_authentic2_config(app_configs, **kwargs):
    from .idp.saml import app_settings
    errors = []

    if not settings.DEBUG and (app_settings.is_default('SIGNATURE_PUBLIC_KEY') or \
            app_settings.is_default('SIGNATURE_PRIVATE_KEY')):
        errors.append(
            Warning(
                'You should not use default SAML keys in production',
                hint='Generate new RSA keys and change the value of A2_IDP_SAML2_SIGNATURE_PUBLIC_KEY and A2_IDP_SAML2_SIGNATURE_PRIVATE_KEY in your setting file',
            )
        )
    return errors

if django.VERSION >= (1, 8):
    check_authentic2_config = register(Tags.security, deploy=True)(check_authentic2_config)
else:
    check_authentic2_config = register()(check_authentic2_config)
