from django.db import models
from django.db.models import query
from django.contrib.contenttypes.models import ContentType

from . import constants, utils

class AbstractBaseManager(models.Manager):
    def get_by_natural_key(self, uuid):
        return self.get(uuid=uuid)

class OperationManager(models.Manager):
    def get_by_natural_key(self, slug):
        return self.get(slug=slug)

    def has_perm(self, user, operation_slug, object_or_model, ou=None):
        '''Test if an user can do the operation given by operation_slug
           on the given object_or_model eventually scoped by an organizational
           unit given by ou.

           Returns True or False.
        '''
        ou_query = query.Q(ou__isnull=True)
        if ou:
            ou_query |= query.Q(ou=ou.as_scope())
        ct = ContentType.objects.get_for_model(object_or_model)
        target_query = query.Q(
                target_ct=ContentType.objects.get_for_model(ContentType),
                target_id=ct.pk)
        if isinstance(object_or_model, models.Model):
            target_query |= query.Q(
                    target_ct=ct,
                    target_id=object.pk)
        Permission = utils.get_permission_model()
        qs = Permission.objects.for_user(user)
        qs = qs.filter(operation__slug=operation_slug)
        qs = qs.filter(ou_query & target_query)
        return qs.exists()

class PermissionManagerBase(models.Manager):
    def get_by_natural_key(self, operation_slug, ou_nk, target_ct,
            target_nk):
        qs = self.filter(operation__slug=operation__slug)
        if ou_nk:
            OrganizationalUnit = utils.get_ou_model()
            try:
                ou = OrganizationalUnit.objects.get_by_natural_key(*ou_nk)
            except OrganizationalUnit.DoesNotExist:
                raise self.model.DoesNotExist
            qs = qs.filter(ou=ou)
        try:
            target_ct = ContentType.objects.get_by_natural_key(*target_ct)
        except ContentType.DoesNotExist:
            raise self.model.DoesNotExist
        target_model = target_ct.model_class()
        try:
            target = target_model.get_by_natural_key(*target_nk)
        except target_model.DoesNotExist:
            raise self.model.DoesNotExist
        return qs.get(
                target_ct=ContentType.objects.get_for_model(target),
                target_id=target.pk)

class PermissionQueryset(query.QuerySet):
    def by_target_ct(self, target):
        '''Filter permission whose target content-type matches the content
           type of the target argument
        '''
        target_ct = ContentType.objects.get_for_model(target)
        return self.filter(target_ct=target_ct)

    def by_target(self, target):
        '''Filter permission whose target matches target'''
        return self.by_target_ct(target).filter(target_id=target.pk)

    def for_user(self, user):
        '''Retrieve all permissions hold by an user through its role and
           inherited roles.
        '''
        Role = utils.get_role_model()
        roles = Role.objects.for_user(user=user)
        return self.filter(role=roles)

PermissionManager = PermissionManagerBase.from_queryset(PermissionQueryset)

class RoleQuerySet(query.QuerySet):
    def for_user(self, user):
        return self.filter(members=user).parents().distinct()

    def parents(self, include_self=True, annotate=False):
        qs = self.model.objects.filter(child_relation__child=self)
        if include_self:
            qs = self | qs
        qs = qs.distinct()
        if annotate:
            qs = qs.annotate(direct=models.Max('child_relation__direct'))
        return qs

    def children(self, include_self=True, annotate=False):
        qs = self.model.objects.filter(parent_relation__parent=self)
        if include_self:
            qs = self | qs
        qs = qs.distinct()
        if annotate:
            qs = qs.annotate(direct=models.Max('parent_relation__direct'))
        return qs

    def all_members():
        User = get_user_model()
        return User.objects.filter(Q(roles=self)|Q(roles__parent_relation__parent=self))

    def by_admin_scope_ct(self, admin_scope):
        admin_scope_ct = ContentType.objects.get_for_model(admin_scope)
        return self.filter(admin_scope_ct=admin_scope_ct)


RoleManager = AbstractBaseManager.from_queryset(RoleQuerySet)

class RoleParentingManager(models.Manager):
    def get_by_natural_key(self, parent_nk, child_nk, direct):
        Role = utils.get_role_model()
        try:
            parent = Role.objects.get_by_natural_key(*parent_nk)
        except Role.DoesNotExist:
            raise self.model.DoesNotExist
        try:
            child = Role.objects.get_by_natural_key(*child_nk)
        except Role.DoesNotExist:
            raise self.model.DoesNotExist
        return self.get(parent=parent, child=child, direct=direct)

    def update_transitive_closure(self):
        '''Recompute the transitive closure of the inheritance relation
           from scratch. Add missing indirect relations and delete
           obsolete indirect relations.
        '''
        # existing indirect paths
        old = set(self.filter(direct=False).values_list('parent_id', 'child_id'))
        # existing direct paths
        ris = set(self.filter(direct=True).values_list('parent_id', 'child_id'))
        add = set()
        new = set()
        old_new = ris

        # Start computing new indirect paths
        while True:
            for (i,j) in ris:
                for (k,l) in old_new:
                    if j == k and (i, l) not in ris:
                        new.add((i, l))
            if old_new != ris:
                for (i,j) in old_new:
                    for (k,l) in ris:
                        if j == k and (i, l) not in ris:
                            new.add((i, l))
            if not new:
                break
            add.update(new)
            ris.update(new)
            old_new = new
            new = set()
        # Create new relations
        self.model.objects.bulk_create(self.model(
            parent_id=a,
            child_id=b,
            direct=False) for a, b in add-old)
        # Delete old ones
        obsolete = old-add
        if obsolete:
	    queries = (query.Q(parent_id=a, child_id=b, direct=False) for a, b in obsolete)
            self.model.objects.filter(reduce(query.Q.__or__, queries)).delete()
