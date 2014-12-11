import sys
import os
import django

__version__ = "2.1.11"

# vendor contains incorporated dependencies
sys.path.append(os.path.join(os.path.dirname(__file__), 'vendor'))

if django.VERSION >= (1,7):
    from django.apps import AppConfig

    class Authentic2Config(AppConfig):
        name = 'authentic2'
        label = 'authentic2'

        def ready(self):
            from . import fix_user_model
    default_app_config = 'authentic2.Authentic2Config'
