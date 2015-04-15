import sys
import os

# vendor contains incorporated dependencies
sys.path.append(os.path.join(os.path.dirname(__file__), 'vendor'))

from django.apps import AppConfig

class Authentic2Config(AppConfig):
    name = 'authentic2'
    label = 'authentic2'

    def ready(self):
        from . import plugins
        plugins.init()
    default_app_config = 'authentic2.Authentic2Config'
