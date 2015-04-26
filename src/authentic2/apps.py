from django.apps import AppConfig

from . import plugins

class Authentic2Config(AppConfig):
    name = 'authentic2'
    verbose_name = 'Authentic2'

    def ready(self):
        plugins.init()
