import re

from django.apps import AppConfig
from django.views import debug

from . import plugins


class Authentic2Config(AppConfig):
    name = 'authentic2'
    verbose_name = 'Authentic2'

    def ready(self):
        plugins.init()
        debug.HIDDEN_SETTINGS = re.compile(
            'API|TOKEN|KEY|SECRET|PASS|PROFANITIES_LIST|SIGNATURE|LDAP')
