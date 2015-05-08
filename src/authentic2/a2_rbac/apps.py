from django.apps import AppConfig


class Authentic2RBACConfig(AppConfig):
    name = 'authentic2.a2_rbac'
    verbose_name = 'Authentic2 RBAC'

    def ready(self):
        from . import signal_handlers, models
        from django.db.models.signals import post_save, post_migrate
        from django.contrib.contenttypes.models import ContentType
        from authentic2.models import Service

        # update rbac on save to contenttype, ou and roles
        post_save.connect(
            signal_handlers.update_rbac_on_save,
            sender=models.OrganizationalUnit)
        post_save.connect(
            signal_handlers.update_rbac_on_save,
            sender=models.Role)
        post_save.connect(
            signal_handlers.update_rbac_on_save,
            sender=ContentType)
        # keep service role and service ou field in sync
        post_save.connect(
            signal_handlers.update_service_role_ou,
            sender=Service)
        post_migrate.connect(
            signal_handlers.create_default_ou,
            sender=self)
        post_migrate.connect(
            signal_handlers.post_migrate_update_rbac,
            sender=self)
