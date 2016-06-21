from django.contrib.contenttypes.models import ContentType

from django_rbac.models import ADMIN_OP
from django_rbac.managers import RoleManager as BaseRoleManager, AbstractBaseManager
from django_rbac.utils import get_operation
from django_rbac import utils as rbac_utils


class OrganizationalUnitManager(AbstractBaseManager):
    def get_by_natural_key(self, slug):
        return self.get(slug=slug)


class RoleManager(BaseRoleManager):
    def get_admin_role(self, instance, name, slug, ou=None, operation=ADMIN_OP,
                       update_name=False, update_slug=False, permissions=(),
                       self_administered=False):
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
                                          update_name=update_name,
                                          update_slug=update_slug)
        permissions = set(permissions)
        permissions.add(perm)
        if self_administered:
            self_perm = admin_role.add_self_administration()
            permissions.add(self_perm)
        if set(admin_role.permissions.all()) != permissions:
            for permission in permissions:
                admin_role.permissions.through.objects.get_or_create(role=admin_role,
                                                                     permission=permission)
        return admin_role

    def get_mirror_role(self, instance, name, slug, ou=None,
                        update_name=False, update_slug=False):
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
        if update_slug and not created and role.slug != slug:
            role.slug = slug
            role.save()
        return role

    def get_by_natural_key(self, slug, ou_natural_key, service_natural_key):
        kwargs = {'slug': slug}
        if ou_natural_key is None:
            kwargs['ou__isnull'] = True
        else:
            OU = rbac_utils.get_ou_model()
            try:
                ou = OU.objects.get_by_natural_key(*ou_natural_key)
            except OU.DoesNotExist:
                raise self.model.DoesNotExist
            kwargs['ou'] = ou
        if service_natural_key is None:
            kwargs['service__isnull'] = True
        else:
            # XXX: prevent an import loop
            from authentic2.models import Service

            try:
                service = Service.objects.get_by_natural_key(*service_natural_key)
            except Service.DoesNotExist:
                raise self.model.DoesNotExist
            kwargs['service'] = service
        return self.get(**kwargs)
