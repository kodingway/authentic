import operator
import hashlib

from django.utils.text import slugify
from django.utils.translation import ugettext_lazy as _
from django.db import models
from django.conf import settings
from django.db.models.query import Q, Prefetch
try:
    from django.contrib.contenttypes.fields import GenericForeignKey, \
        GenericRelation
except ImportError:
    # Django < 1.8
    from django.contrib.contenttypes.generic import GenericForeignKey, \
        GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, _user_get_all_permissions, \
    _user_has_perm, _user_has_module_perms, Permission as AuthPermission
from django.contrib import auth

from . import utils, constants, managers


class AbstractBase(models.Model):
    '''Abstract base model for all models having a name and uuid and a
       slug
    '''
    uuid = models.CharField(
        max_length=32,
        verbose_name=_('uuid'),
        unique=True,
        default=utils.get_hex_uuid)
    name = models.CharField(
        max_length=256,
        verbose_name=_('name'))
    slug = models.SlugField(
        max_length=256,
        verbose_name=_('slug'))
    description = models.TextField(
        verbose_name=_('description'),
        blank=True)

    objects = managers.AbstractBaseManager()

    def __unicode__(self):
        return self.name

    def __repr__(self):
        return '<{0} {1} {2}>'.format(self.__class__.__name__, repr(self.slug),
                                      repr(self.name))

    def save(self, *args, **kwargs):
        # truncate slug and add a hash if it's too long
        if not self.slug:
            self.slug = slugify(unicode(self.name)).lstrip('_')
        if len(self.slug) > 256:
            self.slug = self.slug[:252] + \
                hashlib.md5(self.slug).hexdigest()[:4]
        return super(AbstractBase, self).save(*args, **kwargs)

    def natural_key(self):
        return [self.uuid]

    class Meta:
        abstract = True


class AbstractOrganizationalUnitScopedBase(models.Model):
    '''Base abstract model class for model needing to be scoped by ou'''
    ou = models.ForeignKey(
        to=utils.get_ou_model_name(),
        verbose_name=_('organizational unit'),
        swappable=True,
        blank=True,
        null=True)

    class Meta:
        abstract = True


class OrganizationalUnitAbstractBase(AbstractBase):
    class Meta:
        abstract = True

    def as_scope(self):
        '''When used as scope to find permissions. Can return a queryset
           in a swapped model if for example your OU are hierarchical.

           Must return an OrganizationalUnit or a queryset.
        '''
        return self


class OrganizationalUnit(OrganizationalUnitAbstractBase):
    class Meta:
        verbose_name = _('organizational unit')
        verbose_name_plural = _('organizational units')
        swappable = constants.RBAC_OU_MODEL_SETTING


class Operation(models.Model):
    name = models.CharField(
        max_length=32,
        verbose_name=_('name'))
    slug = models.CharField(
        max_length=32,
        verbose_name=_('slug'),
        unique=True)

    def natural_key(self):
        return [self.slug]

    def __unicode__(self):
        return unicode(_(self.name))

    objects = managers.OperationManager()


class PermissionAbstractBase(models.Model):
    operation = models.ForeignKey(
        to='Operation',
        verbose_name=_('operation'))
    ou = models.ForeignKey(
        to=utils.get_ou_model_name(),
        verbose_name=_('organizational unit'),
        related_name='scoped_permission',
        null=True)
    target_ct = models.ForeignKey(
        to='contenttypes.ContentType',
        related_name='+')
    target_id = models.PositiveIntegerField()
    target = GenericForeignKey(
        'target_ct',
        'target_id')

    objects = managers.PermissionManager()

    def natural_key(self):
        return [self.operation.slug, self.ou and
                self.ou.natural_key(),
                self.target and self.target_ct.natural_key(),
                self.target and self.target.natural_key()]

    def __unicode__(self):
        ct = ContentType.objects.get_for_id(self.target_ct_id)
        ct_ct = ContentType.objects.get_for_model(ContentType)
        if ct == ct_ct:
            target = ContentType.objects.get_for_id(self.target_id)
            s = u'{0} / {1}'.format(self.operation, target)
        else:
            s = u'{0} / {1} / {2}'.format(self.operation, ct,
                                          self.target)
        if self.ou:
            s += _(u' (scope "{0}")').format(self.ou)
        return s

    class Meta:
        abstract = True
        # FIXME: it's still allow non-unique permission with ou=null
        unique_together = (
            ('operation', 'ou', 'target_ct', 'target_id'),
        )


class Permission(PermissionAbstractBase):
    class Meta:
        swappable = constants.RBAC_PERMISSION_MODEL_SETTING
        verbose_name = _('permission')
        verbose_name_plural = _('permissions')


class RoleAbstractBase(AbstractOrganizationalUnitScopedBase, AbstractBase):
    members = models.ManyToManyField(
        to=settings.AUTH_USER_MODEL,
        swappable=True,
        blank=True,
        related_name='roles')
    permissions = models.ManyToManyField(
        to=utils.get_permission_model_name(),
        related_name='roles',
        blank=True)

    objects = managers.RoleQuerySet.as_manager()

    def add_child(self, child):
        RoleParenting = utils.get_role_parenting_model()
        RoleParenting.objects.get_or_create(parent=self, child=child)

    def remove_child(self, child):
        RoleParenting = utils.get_role_parenting_model()
        RoleParenting.objects.filter(parent=self, child=child,
                                     direct=True).delete()

    def add_parent(self, parent):
        RoleParenting = utils.get_role_parenting_model()
        RoleParenting.objects.get_or_create(parent=parent, child=self)

    def remove_parent(self, parent):
        RoleParenting = utils.get_role_parenting_model()
        RoleParenting.objects.filter(child=self, parent=parent,
                                     direct=True).delete()

    def parents(self, include_self=True, annotate=False):
        return self.__class__.objects.filter(pk=self.pk) \
            .parents(include_self=include_self, annotate=annotate)

    def children(self, include_self=True, annotate=False):
        return self.__class__.objects.filter(pk=self.pk) \
            .children(include_self=include_self, annotate=annotate)

    def all_members(self):
        User = get_user_model()
        prefetch = Prefetch('roles',
                            queryset=self.__class__.objects.filter(pk=self.pk),
                            to_attr='direct')
        return User.objects.filter(Q(roles=self) |
                                   Q(roles__parent_relation__parent=self)) \
                           .distinct() \
                           .prefetch_related(prefetch)

    def is_direct(self):
        if hasattr(self, 'direct'):
            if self.direct is None:
                return True
            return bool(self.direct)
        return None

    class Meta:
        abstract = True


class Role(RoleAbstractBase):
    class Meta:
        verbose_name = _('role')
        verbose_name_plural = _('roles')
        swappable = constants.RBAC_ROLE_MODEL_SETTING


class RoleParentingAbstractBase(models.Model):
    parent = models.ForeignKey(
        to=utils.get_role_model_name(),
        swappable=True,
        related_name='child_relation')
    child = models.ForeignKey(
        to=utils.get_role_model_name(),
        swappable=True,
        related_name='parent_relation')
    direct = models.BooleanField(
        default=True,
        blank=True)

    objects = managers.RoleParentingManager()

    def natural_key(self):
        return [self.parent.natural_key(), self.child.natural_key(),
                self.direct]

    class Meta:
        abstract = True
        unique_together = (('parent', 'child', 'direct'),)
        # covering indexes
        index_together = (('child', 'parent', 'direct'),)


class RoleParenting(RoleParentingAbstractBase):
    class Meta:
        verbose_name = _('role parenting relation')
        verbose_name_plural = _('role parenting relations')
        swappable = constants.RBAC_ROLE_PARENTING_MODEL_SETTING


class PermissionMixin(models.Model):
    """
    A mixin class that adds the fields and methods necessary to support
    Django's Group and Permission model using the ModelBackend.
    """
    is_superuser = models.BooleanField(
        _('superuser status'), default=False,
        help_text=_('Designates that this user has all permissions '
                    'without explicitly assigning them.'))
    groups = models.ManyToManyField(
        to=Group,
        verbose_name=_('groups'),
        blank=True,
        help_text=_('The groups this user belongs to. A user will get '
                    'all permissions granted to each of his/her '
                    'group.'),
        related_name="user_set", related_query_name="user")
    user_permissions = models.ManyToManyField(
        to=AuthPermission, verbose_name=_('user permissions'),
        blank=True, help_text=_('Specific permissions for this user.'),
        related_name="user_set", related_query_name="user")

    class Meta:
        abstract = True

    def get_group_permissions(self, obj=None):
        """
        Returns a list of permission strings that this user has through their
        groups. This method queries all available auth backends. If an object
        is passed in, only permissions matching this object are returned.
        """
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_group_permissions"):
                permissions.update(backend.get_group_permissions(self, obj))
        return permissions

    def get_all_permissions(self, obj=None):
        return _user_get_all_permissions(self, obj)

    def has_perm(self, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general. If an object is
        provided, permissions for this specific object are checked.
        """

        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions. If
        object is passed, it checks if the user has all required perms for this
        object.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permissions in the given app label.
        Uses pretty much the same logic as has_perm, above.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        return _user_has_module_perms(self, app_label)

    def filter_by_perm(self, perm_or_perms, qs):
        results = []
        for backend in auth.get_backends():
            if hasattr(backend, "filter_by_perm"):
                results.append(backend.filter_by_perm(self, perm_or_perms, qs))
        if results:
            return reduce(operator.__or__, results)
        else:
            return qs

    def has_perm_any(self, perm_or_perms):
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        for backend in auth.get_backends():
            if hasattr(backend, "has_perm_any"):
                if backend.has_perm_any(self, perm_or_perms):
                    return True
        return False

    def has_ou_perm(self, perm, ou):
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        for backend in auth.get_backends():
            if hasattr(backend, "has_ou_perm"):
                if backend.has_ou_perm(self, perm, ou):
                    return True
        return False

ADMIN_OP = Operation(name=_('Management'), slug='admin')
CHANGE_OP = Operation(name=_('Change'), slug='change')
DELETE_OP = Operation(name=_('Delete'), slug='delete')
ADD_OP = Operation(name=_('Add'), slug='add')
VIEW_OP = Operation(name=_('View'), slug='view')
