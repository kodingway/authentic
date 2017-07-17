from django.apps import AppConfig


class AppConfig(AppConfig):
    name = 'authentic2.manager'
    verbose_name = 'Authentic2 Manager'

    def ready(self):
        from django.db.models.signals import post_save
        from django_rbac.utils import get_ou_model

        post_save.connect(
            self.post_save_ou,
            sender=get_ou_model())

    def post_save_ou(self, *args, **kwargs):
        from . import utils
        utils.get_ou_count.cache.clear()
