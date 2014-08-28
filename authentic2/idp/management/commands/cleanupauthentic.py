import logging

from django.core.management.base import NoArgsCommand
from django.db import models

class Command(NoArgsCommand):
    help = 'Clean expired models of authentic2.'

    def handle_noargs(self, **options):
        log = logging.getLogger(__name__)

        for app in models.get_apps():
            for model in models.get_models(app):
                # only models from authentic2
                if not model.__module__.startswith('authentic2'):
                    continue
                try:
                    self.cleanup_model(model)
                except:
                    log.exception('cleanup of model %s failed', model)

    def cleanup_model(model):
        manager = getattr(model, 'objects', None)
        if hasattr(manager, 'cleanup'):
            manager.cleanup()
