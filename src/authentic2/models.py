import time
import urlparse
import uuid
from django.utils.http import urlquote
from django.conf import settings
from django.db import models
from django.db.models.query import Q
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError, FieldDoesNotExist
from django.contrib.contenttypes.models import ContentType

from model_utils.managers import QueryManager

from . import attribute_kinds
from authentic2.a2_rbac.models import Role
from authentic2.a2_rbac.utils import get_default_ou
from django_rbac.utils import get_role_model_name

try:
    from django.contrib.contenttypes.fields import GenericForeignKey
except ImportError:
    from django.contrib.contenttypes.generic import GenericForeignKey
from django.contrib.contenttypes.models import ContentType

from . import managers
from .utils import ServiceAccessDenied


class DeletedUser(models.Model):
    '''Record users to delete'''

    objects = managers.DeletedUserManager()

    user = models.ForeignKey(settings.AUTH_USER_MODEL,
            verbose_name=_('user'))
    creation = models.DateTimeField(auto_now_add=True,
            verbose_name=_('creation date'))

    class Meta:
        verbose_name = _('user to delete')
        verbose_name_plural = _('users to delete')

class UserExternalId(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
            verbose_name=_('user'))
    source = models.URLField(max_length=256,
            verbose_name=_('source'))
    external_id = models.CharField(max_length=256,
            verbose_name=_('external id'))
    created = models.DateTimeField(auto_now_add=True,
            verbose_name=_('creation date'))
    updated = models.DateTimeField(auto_now=True,
            verbose_name=_('last update date'))

    def __unicode__(self):
        return u'{0} is {1} on {2}'.format(
                self.user, self.external_id, self.source)

    def __repr__(self):
        return '<UserExternalId user: {0!r} source: {1!r} ' \
               'external_id: {2!r} created: {3} updated: {4}' \
               .format(self.user_id, self.source, self.external_id,
                       self.created, self.updated)

    class Meta:
        verbose_name = _('user external id')
        verbose_name_plural = _('user external ids')

class AuthenticationEvent(models.Model):
    '''Record authentication events whatever the source'''
    when = models.DateTimeField(auto_now=True,
            verbose_name=_('when'))
    who = models.CharField(max_length=80,
            verbose_name=_('who'))
    how = models.CharField(max_length=32,
            verbose_name=_('how'))
    nonce = models.CharField(max_length=255,
            verbose_name=_('nonce'))

    objects = managers.AuthenticationEventManager()

    class Meta:
        verbose_name = _('authentication log')
        verbose_name_plural = _('authentication logs')

    def __unicode__(self):
        return _('Authentication of %(who)s by %(how)s at %(when)s') % \
            self.__dict__

class LogoutUrlAbstract(models.Model):
    logout_url = models.URLField(verbose_name=_('url'), help_text=_('you can use a {} '
        'to pass the URL of the success icon, ex.: '
        'http://example.com/logout?next={}'), max_length=255, blank=True, null=True)
    logout_use_iframe = models.BooleanField(
            verbose_name=_('use an iframe instead of an img tag for logout'),
            default=False)
    logout_use_iframe_timeout = models.PositiveIntegerField(
            verbose_name=_('iframe logout timeout (ms)'),
            help_text=_('if iframe logout is used, it\'s the time between the '
                'onload event for this iframe and the moment we consider its '
                'loading to be really finished'),
            default=300)

    def get_logout_url(self, request):
        ok_icon_url = request.build_absolute_uri(urlparse.urljoin(settings.STATIC_URL,
                'authentic2/images/ok.png')) + '?nonce=%s' % time.time()
        return self.logout_url.format(urlquote(ok_icon_url))

    class Meta:
        abstract = True


class LogoutUrl(LogoutUrlAbstract):
    content_type = models.ForeignKey(ContentType,
            verbose_name=_('content type'))
    object_id = models.PositiveIntegerField(
            verbose_name=_('object identifier'))
    provider = GenericForeignKey('content_type', 'object_id')

    class Meta:
        verbose_name = _('logout URL')
        verbose_name_plural = _('logout URL')


class Attribute(models.Model):
    label = models.CharField(verbose_name=_('label'), max_length=63,
            unique=True)
    description = models.TextField(verbose_name=_('description'), blank=True)
    name = models.SlugField(verbose_name=_('name'), max_length=256,
            unique=True)
    required = models.BooleanField(
            verbose_name=_('required'),
            blank=True, default=False)
    asked_on_registration = models.BooleanField(
            verbose_name=_('asked on registration'),
            blank=True, default=False)
    user_editable = models.BooleanField(
            verbose_name=_('user editable'),
            blank=True, default=False)
    user_visible = models.BooleanField(
            verbose_name=_('user visible'),
            blank=True, default=False)
    multiple = models.BooleanField(
            verbose_name=_('multiple'),
            blank=True, default=False)
    kind = models.CharField(max_length=16,
            verbose_name=_('kind'))
    disabled = models.BooleanField(verbose_name=_('disabled'),
                                   blank=True, default=False)
    searchable = models.BooleanField(
        verbose_name=_('searchable'),
        blank=True, default=False)

    objects = managers.AttributeManager(disabled=False)
    all_objects = managers.AttributeManager()

    registration_attributes = QueryManager(asked_on_registration=True)
    user_attributes = QueryManager(user_editable=True)

    def get_form_field(self, **kwargs):
        kwargs['label'] = self.label
        kwargs['required'] = self.required
        if self.description:
            kwargs['help_text'] = self.description
        return attribute_kinds.get_form_field(self.kind, **kwargs)

    def get_kind(self):
        return attribute_kinds.get_kind(self.kind)

    def contribute_to_form(self, form, **kwargs):
        form.fields[self.name] = self.get_form_field(**kwargs)

    def get_value(self, owner, verified=None):
        kind = self.get_kind()
        deserialize = kind['deserialize']
        atvs = AttributeValue.objects.with_owner(owner)
        if verified is True or verified is False:
            atvs = atvs.filter(verified=verified)
        if self.multiple:
            result = []
            for atv in atvs.filter(attribute=self, multiple=True):
                result.append(deserialize(atv.content))
            return result
        else:
            try:
                atv = atvs.get(attribute=self, multiple=False)
                return deserialize(atv.content)
            except AttributeValue.DoesNotExist:
                return kind['default']

    def set_value(self, owner, value, verified=False):
        serialize = self.get_kind()['serialize']
        # setting to None is to delete
        if value is None:
            AttributeValue.objects.with_owner(owner).filter(attribute=self).delete()
            return

        if self.multiple:
            assert isinstance(value, (list, set, tuple))
            values = value
            for value in values:
                content = serialize(value)
                av, created = AttributeValue.objects.get_or_create(
                        content_type=ContentType.objects.get_for_model(owner),
                        object_id=owner.pk,
                        attribute=self,
                        multiple=True,
                        content=content,
                        defaults={'verified': verified})
                if not created:
                    av.verified = verified
                    av.save()
        else:
            content = serialize(value)
            av, created = AttributeValue.objects.get_or_create(
                    content_type=ContentType.objects.get_for_model(owner),
                    object_id=owner.pk,
                    attribute=self,
                    multiple=False,
                    defaults={'content': content, 'verified': verified})
            if not created:
                av.content = content
                av.verified = verified
                av.save()

        # if owner has a modified field, update it
        try:
            modified = owner.__class__._meta.get_field('modified')
        except FieldDoesNotExist:
            pass
        else:
            if getattr(modified, 'auto_now', False):
                owner.save(update_fields=['modified'])

    def natural_key(self):
        return (self.name,)

    def __unicode__(self):
        return self.label

    class Meta:
        verbose_name = _('attribute definition')
        verbose_name_plural = _('attribute definitions')

class AttributeValue(models.Model):
    content_type = models.ForeignKey('contenttypes.ContentType',
            verbose_name=_('content type'))
    object_id = models.PositiveIntegerField(
            verbose_name=_('object identifier'),
            db_index=True)
    owner = GenericForeignKey('content_type', 'object_id')

    attribute = models.ForeignKey('Attribute',
            verbose_name=_('attribute'))
    multiple = models.BooleanField(default=False)

    content = models.TextField(verbose_name=_('content'), db_index=True)
    verified = models.BooleanField(default=False)

    objects = managers.AttributeValueManager()

    def to_python(self):
        deserialize = self.attribute.get_kind()['deserialize']
        return deserialize(self.content)

    def natural_key(self):
        if not hasattr(self.owner, 'natural_key'):
            return self.id
        return (self.content_type.natural_key(), self.owner.natural_key(),
                self.attribute.natural_key())

    def save(self, *args, **kwargs):
        changed = False
        if self.attribute.name in ('first_name', 'last_name'):
            setattr(self.owner, self.attribute.name, self.to_python())
            changed = True
        if changed:
            self.owner.save(nosync=True)
        return super(AttributeValue, self).save(*args, **kwargs)

    class Meta:
        verbose_name = _('attribute value')
        verbose_name_plural = _('attribute values')
        unique_together = (
            ('content_type', 'object_id', 'attribute', 'multiple', 'content'),
        )


class PasswordReset(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
            verbose_name=_('user'))

    def save(self, *args, **kwargs):
        if self.user_id and not self.user.has_usable_password():
            self.user.set_password(uuid.uuid4().hex)
            self.user.save()
        return super(PasswordReset, self).save(*args, **kwargs)

    class Meta:
        verbose_name = _('password reset')
        verbose_name_plural = _('password reset')

    def __unicode__(self):
        return unicode(self.user)


class Service(models.Model):
    name = models.CharField(
        verbose_name=_('name'),
        max_length=128)
    slug = models.SlugField(
        verbose_name=_('slug'),
        max_length=128)
    ou = models.ForeignKey(
        verbose_name=_('organizational unit'),
        to='a2_rbac.OrganizationalUnit',
        null=True,
        blank=True,
        swappable=False)
    authorized_roles = models.ManyToManyField(
        get_role_model_name(), verbose_name=_('authorized services'),
        through='AuthorizedRole', through_fields=('service', 'role'),
        related_name='authorized_roles', blank=True)
    unauthorized_url = models.URLField(
        verbose_name=_('callback url when unauthorized'),
        max_length=256, null=True, blank=True)

    objects = managers.ServiceManager()

    def clean(self):
        errors = {}

        if self.ou is None and self.__class__.objects.exclude(pk=self.pk) \
               .filter(slug=self.slug, ou__isnull=True):
            errors['slug'] = ValidationError(
                _('The slug must be unique for this ou'),
                code='duplicate-slug')
        if self.ou is None and self.__class__.objects.exclude(pk=self.pk) \
               .filter(name=self.name, ou__isnull=True):
            errors['name'] = ValidationError(
                _('The name must be unique for this ou'),
                code='duplicate-name')
        if errors:
            raise ValidationError(errors)

    class Meta:
        verbose_name = _('base service model')
        verbose_name_plural = _('base service models')
        unique_together = (
                ('slug', 'ou'),
        )

    def natural_key(self):
        return [self.ou and self.ou.natural_key(), self.slug]

    def __unicode__(self):
        return self.name

    def __repr__(self):
        return '<%s %r>' % (self.__class__.__name__, unicode(self))

    def authorize(self, user):
        if not self.authorized_roles.exists():
            return True
        if user.roles_and_parents().filter(authorized_roles=self).exists():
            return True
        raise ServiceAccessDenied(service=self)

    def add_authorized_role(self, role):
        authorization, created = AuthorizedRole.objects.get_or_create(
            service=self, role=role)
        return authorization

    def remove_authorized_role(self, role):
        try:
            authorization = AuthorizedRole.objects.get(service=self, role=role)
            authorization.delete()
        except AuthorizedRole.DoesNotExist:
            pass
        return True

    def to_json(self, roles=None):
        if roles is None:
            roles = Role.objects.all()
        roles = roles.filter(Q(service=self)|Q(ou=self.ou, service__isnull=True))
        return {
            'name': self.name,
            'slug': self.slug,
            'ou': self.ou.name if self.ou else None,
            'ou__uuid': self.ou.uuid if self.ou else None,
            'ou__name': self.ou.name if self.ou else None,
            'ou__slug': self.ou.slug if self.ou else None,
            'roles': [role.to_json() for role in roles],
        }


class AuthorizedRole(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    role = models.ForeignKey(get_role_model_name(), on_delete=models.CASCADE)
