from django.utils.http import urlquote
from django.db import models
from django.db.models.fields import NOT_PROVIDED
from django.utils import timezone
from django.core.mail import send_mail
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError, MultipleObjectsReturned
try:
    from django.contrib.contenttypes.fields import GenericRelation
except ImportError:
    from django.contrib.contenttypes.generic import GenericRelation

from django_rbac.backends import DjangoRBACBackend
from django_rbac.models import PermissionMixin
from django_rbac.utils import get_role_parenting_model

from authentic2 import utils, validators, app_settings
from authentic2.decorators import errorcollector
from authentic2.models import Service, AttributeValue, Attribute

from .managers import UserManager
from .base_user import AbstractBaseUser


class Attributes(object):
    def __init__(self, owner):
        super(Attributes, self).__setattr__('owner', owner)

    def __setattr__(self, name, value):
        try:
            at = Attribute.objects.get(name=name)
            at.set_value(self.owner, value)
        except Attribute.DoesNotExist:
            raise AttributeError(name)

    def __getattr__(self, name):
        try:
            return Attribute.objects.get(name=name).get_value(self.owner)
        except Attribute.DoesNotExist:
            raise AttributeError(name)


class AttributesDescriptor(object):
    def __get__(self, obj, objtype):
        return Attributes(obj)


class User(AbstractBaseUser, PermissionMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    Username, password and email are required. Other fields are optional.
    """
    uuid = models.CharField(_('uuid'), max_length=32,
            default=utils.get_hex_uuid, editable=False, unique=True)
    username = models.CharField(_('username'), max_length=256, null=True, blank=True)
    first_name = models.CharField(_('first name'), max_length=64, blank=True)
    last_name = models.CharField(_('last name'), max_length=64, blank=True)
    email = models.EmailField(_('email address'), blank=True,
            validators=[validators.EmailValidator], max_length=254)
    is_staff = models.BooleanField(_('staff status'), default=False,
        help_text=_('Designates whether the user can log into this admin '
                    'site.'))
    is_active = models.BooleanField(_('active'), default=True,
        help_text=_('Designates whether this user should be treated as '
                    'active. Unselect this instead of deleting accounts.'))
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    ou = models.ForeignKey(
        verbose_name=_('organizational unit'),
        to='a2_rbac.OrganizationalUnit',
        blank=True,
        null=True,
        swappable=False)


    objects = UserManager()
    attributes = AttributesDescriptor()

    attribute_values = GenericRelation('authentic2.AttributeValue')

    USERNAME_FIELD = 'uuid'
    REQUIRED_FIELDS = ['username', 'email']
    USER_PROFILE = ('first_name', 'last_name', 'email')

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        permissions = (
            ('view_user', 'can see available users'),
        )
        ordering = ('first_name', 'last_name', 'email', 'username')

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip() or self.username or self.email

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name or self.username or self.email or self.uuid[:6]

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])

    def get_username(self):
        "Return the identifying username for this User"
        return self.username or self.email or self.get_full_name() or self.uuid

    def roles_and_parents(self):
        qs1 = self.roles.all()
        qs2 = qs1.model.objects.filter(child_relation__child=qs1)
        qs = (qs1 | qs2).order_by('name').distinct()
        RoleParenting = get_role_parenting_model()
        rp_qs = RoleParenting.objects.filter(child=qs1)
        qs = qs.prefetch_related(models.Prefetch(
            'child_relation', queryset=rp_qs), 'child_relation__parent')
        qs = qs.prefetch_related(models.Prefetch(
            'members', queryset=self.__class__.objects.filter(pk=self.pk), to_attr='member'))
        return qs

    def __unicode__(self):
        human_name = self.username or self.email or self.get_full_name()
        short_id = self.uuid[:6]
        return u'%s (%s)' % (human_name, short_id)

    def __repr__(self):
        return '<User: %r>' % unicode(self)

    def clean_fields(self, exclude=None):
        errors = {}

        with errorcollector(errors):
            super(User, self).clean_fields(exclude=exclude)

        exclude = exclude or []

        model = self.__class__
        qs = model.objects
        if self.pk:
            qs = qs.exclude(pk=self.pk)
        if self.ou_id:
            qs = qs.filter(ou_id=self.ou_id)
        else:
            qs = qs.filter(ou__isnull=True)

        if 'username' not in exclude and self.username and app_settings.A2_USERNAME_IS_UNIQUE:
            try:
                try:
                    qs.get(username=self.username)
                except MultipleObjectsReturned:
                    pass
            except model.DoesNotExist:
                pass
            else:
                errors.setdefault('username', []).append(
                    _('This username is already in use. Please supply a different username.'))
        if 'email' not in exclude and self.email and app_settings.A2_EMAIL_IS_UNIQUE:
            try:
                try:
                    qs.get(email__iexact=self.email)
                except MultipleObjectsReturned:
                    pass
            except model.DoesNotExist:
                pass
            else:
                errors.setdefault('email', []).append(
                    _('This email address is already in use. Please supply a different email '
                      'address.'))
        if errors:
            raise ValidationError(errors)

    def natural_key(self):
        return (self.uuid,)

    def has_verified_attributes(self):
        return AttributeValue.objects.with_owner(self).filter(verified=True).exists()

    def to_json(self):
        d = {}
        for av in AttributeValue.objects.with_owner(self):
            d[str(av.attribute.name)] = av.to_python()
        d.update({
            'uuid': self.uuid,
            'username': self.username,
            'email': self.email,
            'ou': self.ou.name if self.ou else None,
            'ou__uuid': self.ou.uuid if self.ou else None,
            'ou__slug': self.ou.slug if self.ou else None,
            'ou__name': self.ou.name if self.ou else None,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_superuser': self.is_superuser,
            'roles': [role.to_json() for role in self.roles_and_parents()],
            'services': [service.to_json(roles=self.roles_and_parents()) for service in Service.objects.all()],
        })
        return d

    def save(self, *args, **kwargs):
        sync = not(kwargs.pop('nosync', False))
        rc = super(User, self).save(*args, **kwargs)
        if sync:
            for attr_name in ('first_name', 'last_name'):
                try:
                    attribute = Attribute.objects.get(name=attr_name)
                except Attribute.DoesNotExist:
                    pass
                else:
                    if attribute.get_value(self) != getattr(self, attr_name, None):
                        attribute.set_value(self, getattr(self, attr_name, None))
        return rc
