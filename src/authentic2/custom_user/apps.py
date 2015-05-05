from django.apps import AppConfig

def create_permissions(sender, app_config, **kwargs):
    from django.contrib.auth.models import Group, Permission
    from django.contrib.contenttypes.models import ContentType
    group_ct = ContentType.objects.get_for_model(Group)
    Permission.objects.get_or_create(codename='view_group',
        content_type=group_ct,
        defaults={
          'name': 'Can view groups'
        })
    Permission.objects.get_or_create(codename='change_permissions_group',
        content_type=group_ct,
        defaults={
          'name': 'Can change permissions of groups'
        })

class CustomUserConfig(AppConfig):
    name = 'authentic2.custom_user'
    verbose_name = 'Authentic2 Custom User App'

    def ready(self):
        from django.db.models.signals import post_migrate
        post_migrate.connect(create_permissions)
