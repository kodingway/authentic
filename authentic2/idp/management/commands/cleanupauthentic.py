from django.core.management.base import NoArgsCommand
from django.db import models

class Command(NoArgsCommand):
    help = 'Clean expired models of authentic2.'

    def handle_noargs(self, **options):
        for app in models.get_apps():
            for model in models.get_models(app):
                # only models from authentic2
                if not model.__module__.startswith('authentic2'):
                    continue
                manager = getattr(model, 'objects', None)
                try:
                    manager.cleanup()
                except (AttributeError, TypeError):
                    pass
