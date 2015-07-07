from django.apps import AppConfig


class Authentic2RBACConfig(AppConfig):
    name = 'authentic2.a2_rbac'
    verbose_name = 'Authentic2 RBAC'

    def ready(self):
        from . import signal_handlers, models
        from django.db.models.signals import post_save, post_migrate, pre_save, \
            post_delete
        from django.contrib.contenttypes.models import ContentType
        from authentic2.models import Service

        # update rbac on save to contenttype, ou and roles
        post_save.connect(
            signal_handlers.update_rbac_on_ou_post_save,
            sender=models.OrganizationalUnit)
        post_delete.connect(
            signal_handlers.update_rbac_on_ou_post_delete,
            sender=models.OrganizationalUnit)
        # keep service role and service ou field in sync
        for subclass in Service.__subclasses__():
            post_save.connect(
                signal_handlers.update_service_role_ou,
                sender=subclass)
        post_migrate.connect(
            signal_handlers.create_default_ou,
            sender=self)
