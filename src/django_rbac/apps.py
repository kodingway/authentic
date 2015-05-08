from django.apps import AppConfig


class DjangoRBACConfig(AppConfig):
    name = 'django_rbac'
    verbose_name = 'RBAC engine for Django'

    def ready(self):
        from . import signal_handlers, utils
        from django.db.models.signals import post_save, post_delete, \
            post_migrate

        # update role parenting when new role parenting is created
        post_save.connect(
            signal_handlers.role_parenting_post_save,
            sender=utils.get_role_parenting_model())
        # update role parenting when role parenting is deleted
        post_delete.connect(
            signal_handlers.role_parenting_post_delete,
            sender=utils.get_role_parenting_model())
        # create CRUD operations and admin
        post_migrate.connect(
            signal_handlers.create_base_operations,
            sender=self)
        # update role parenting in post migrate
        post_migrate.connect(
            signal_handlers.fix_role_parenting_closure,
            sender=self)
