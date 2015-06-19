from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.utils.text import slugify
from django.db import models

from django_rbac.models import RoleAbstractBase, PermissionAbstractBase, \
    OrganizationalUnitAbstractBase, RoleParentingAbstractBase, VIEW_OP

try:
    from django.contrib.contenttypes.fields import GenericForeignKey
except ImportError:
    # Django < 1.8
    from django.contrib.contenttypes.generic import GenericForeignKey

from . import managers, fields


class OrganizationalUnit(OrganizationalUnitAbstractBase):
    username_is_unique = models.BooleanField(
        blank=True,
        default=False,
        verbose_name=_('Username is unique'))
    email_is_unique = models.BooleanField(
        blank=True,
        default=False,
        verbose_name=_('Email is unique'))
    default = fields.UniqueBooleanField(
        verbose_name=_('Default organizational unit'))

    class Meta:
        verbose_name = _('organizational unit')
        verbose_name_plural = _('organizational units')
        ordering = ('name',)
        unique_together =(
            ('name',),
            ('slug',),
        )

    def clean(self):
        # if we set this ou as the default one, we must unset the other one if
        # there is
        if self.default:
            qs = self.__class__.objects.filter(default=True)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            qs.update(default=None)
        if self.pk and not self.default \
           and self.__class__.objects.get(pk=self.pk).default:
            raise ValidationError(_('You cannot unset this organizational '
                                    'unit as the default, but you can set '
                                    'another one as the default.'))
        super(OrganizationalUnit, self).clean()

    def get_admin_role(self):
        '''Get or create the generic admin role for this organizational
           unit.
        '''
        name = _('Managers of "{ou}"').format(ou=self)
        slug = '_a2-managers-of-{ou.slug}'.format(ou=self)
        return Role.objects.get_admin_role(
            instance=self, name=name, slug=slug, operation=VIEW_OP,
            update_name=True, update_slug=True)


class Permission(PermissionAbstractBase):
    class Meta:
        verbose_name = _('permission')
        verbose_name_plural = _('permissions')


class Role(RoleAbstractBase):
    admin_scope_ct = models.ForeignKey(
        to='contenttypes.ContentType',
        null=True,
        blank=True,
        verbose_name=_('administrative scope content type'))
    admin_scope_id = models.PositiveIntegerField(
        verbose_name=_('administrative scope id'),
        null=True,
        blank=True)
    admin_scope = GenericForeignKey(
        'admin_scope_ct',
        'admin_scope_id')
    service = models.ForeignKey(
        to='authentic2.Service',
        verbose_name=_('service'),
        null=True,
        blank=True,
        related_name='roles')
    external_id = models.TextField(
        verbose_name=_('external id'),
        blank=True,
        db_index=True)

    def get_admin_role(self, ou=None):
        return self.__class__.objects.get_admin_role(
            self, ou=self.ou,
            name=_('Managers of role "{role}"').format(role=unicode(self)),
            slug='_a2-managers-of-role-{role}'.format(role=slugify(unicode(self))))

    def clean(self):
        super(Role, self).clean()
        if self.slug and self.slug.startswith('_'):
            raise ValidationError(
                {'slug': _('Slug starting with _ are reserved.')})
        if not self.service and not self.admin_scope_ct_id:
            if not self.id and self.__class__.objects.filter(
                    slug=self.slug, ou=self.ou):
                raise ValidationError(
                    {'slug': _('This slug is not unique over this '
                               'organizational unit.')})
            if not self.id and self.__class__.objects.filter(
                    name=self.name, ou=self.ou):
                raise ValidationError(
                    {'name': _('This name is not unique over this '
                               'organizational unit.')})

    def save(self, *args, **kwargs):
        # Service roles can only be part of the same ou as the service
        if self.service:
            self.ou = self.service.ou
        return super(Role, self).save(*args, **kwargs)

    objects = managers.RoleManager()

    class Meta:
        verbose_name = _('role')
        verbose_name_plural = _('roles')
        ordering = ('ou', 'service', 'name',)


class RoleParenting(RoleParentingAbstractBase):
    class Meta:
        verbose_name = _('role parenting relation')
        verbose_name_plural = _('role parenting relations')


class RoleAttribute(models.Model):
    KINDS = (
        ('string', _('string')),
    )
    role = models.ForeignKey(
        to=Role,
        verbose_name=_('role'),
        related_name='attributes')
    name = models.CharField(
        max_length=64,
        verbose_name=_('name'))
    kind = models.CharField(
        max_length=32,
        choices=KINDS,
        verbose_name=_('kind'))
    value = models.TextField(
        verbose_name=_('value'))

    class Meta:
        verbose_name = ('role attribute')
        verbose_name_plural = _('role attributes')
        unique_together = (
            ('role', 'name', 'kind', 'value'),
        )
