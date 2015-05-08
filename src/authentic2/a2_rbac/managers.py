from django.contrib.contenttypes.models import ContentType

from django_rbac.models import ADMIN_OP
from django_rbac.managers import RoleManager as BaseRoleManager
from django_rbac.utils import get_operation
from django_rbac import utils as rbac_utils


class RoleManager(BaseRoleManager):
    def get_admin_role(self, instance, name, slug, ou=None, operation=ADMIN_OP,
                       update_name=False):
        '''Get or create the role of manager's of this object instance'''
        kwargs = {}
        if ou or getattr(instance, 'ou', None):
            ou = kwargs['ou'] = ou or instance.ou
        else:
            kwargs['ou__isnull'] = True
        # find an operation matching the template
        op = get_operation(operation)
        Permission = rbac_utils.get_permission_model()
        perm, created = Permission.objects.get_or_create(
            operation=op,
            target_ct=ContentType.objects.get_for_model(instance),
            target_id=instance.pk,
            **kwargs)
        admin_role = self.get_mirror_role(perm, name, slug, ou=ou,
                                          update_name=update_name)
        self_perm, created = Permission.objects.get_or_create(
            operation=op,
            target_ct=ContentType.objects.get_for_model(admin_role),
            target_id=admin_role.pk,
            **kwargs)
        if perm not in admin_role.permissions.all():
            admin_role.permissions.add(perm)
        if self_perm not in admin_role.permissions.all():
            admin_role.permissions.add(self_perm)
        return admin_role

    def get_mirror_role(self, instance, name, slug, ou=None,
                        update_name=False):
        '''Get or create a role which mirror another model, for example a
           permission.
        '''
        ct = ContentType.objects.get_for_model(instance)
        kwargs = {}
        if ou or getattr(instance, 'ou', None):
            kwargs['ou'] = ou or instance.ou
        else:
            kwargs['ou__isnull'] = True
        role, created = self.prefetch_related('permissions').get_or_create(
            admin_scope_ct=ct,
            admin_scope_id=instance.pk,
            defaults={
                'name': name,
                'slug': slug,
                }, **kwargs)
        if update_name and not created and role.name != name:
            role.name = name
            role.save()
        return role
