import sys
import os
import django

# vendor contains incorporated dependencies
sys.path.append(os.path.join(os.path.dirname(__file__), 'vendor'))

if django.VERSION >= (1,7):
    from django.apps import AppConfig

    class Authentic2Config(AppConfig):
        name = 'authentic2'
        label = 'authentic2'

        def ready(self):
            from . import fix_user_model, compat
            fix_user_model.patch_user_model(compat.get_user_model())
            fix_user_model.patch_email()
    default_app_config = 'authentic2.Authentic2Config'
