from datetime import timedelta
import logging


from django.db import models
from django.db.models.query import QuerySet
from django.utils.timezone import now
from django.utils.http import urlquote
from django.conf import settings
from django.contrib.contenttypes.models import ContentType

from django_rbac.utils import get_ou_model
from model_utils import managers

logger = logging.getLogger(__name__)


class GetBySlugQuerySet(QuerySet):
    def get_by_natural_key(self, slug):
        return self.get(slug=slug)

GetBySlugManager = GetBySlugQuerySet.as_manager


class GetByNameQuerySet(QuerySet):
    def get_by_natural_key(self, name):
        return self.get(name=name)

GetByNameManager = GetByNameQuerySet.as_manager


class DeletedUserManager(models.Manager):
    def delete_user(self, user):
        user.is_active = False
        user.save()
        self.get_or_create(user=user)

    def cleanup(self, threshold=600, timestamp=None):
        '''Delete all deleted users for more than 10 minutes.'''
        not_after = (timestamp or now()) - timedelta(seconds=threshold)
        for deleted_user in self.filter(creation__lte=not_after):
            user = deleted_user.user
            deleted_user.delete()
            user.delete()
            logger.info(u'deleted account %s', user)


class AuthenticationEventManager(models.Manager):
    def cleanup(self):
        # expire after one week
        expire = getattr(settings, 'AUTHENTICATION_EVENT_EXPIRATION', 3600 * 24 * 7)
        self.filter(when__lt=now() - timedelta(seconds=expire)).delete()


class ExpireManager(models.Manager):
    def cleanup(self):
        self.filter(created__lt=now() - timedelta(days=7)).delete()


class GenericQuerySet(QuerySet):
    def for_generic_object(self, model):
        content_type = ContentType.objects.get_for_model(model)
        return self.filter(content_type=content_type, object_id=model.pk)

GenericManager = models.Manager.from_queryset(GenericQuerySet)


class AttributeValueQuerySet(QuerySet):
    def with_owner(self, owner):
        content_type = ContentType.objects.get_for_model(owner)
        return self.filter(content_type=content_type, object_id=owner.pk)

    def get_by_natural_key(self, ct_nk, owner_nk, attribute_nk):
        from .models import Attribute, AttributeValue
        try:
            ct = ContentType.objects.get_by_natural_key(*ct_nk)
        except ContentType.DoesNotExist:
            raise AttributeValue.DoesNotExist
        try:
            owner_class = ct.model_class()
            owner = owner_class.objects.get_by_natural_key(*owner_nk)
        except owner_class.DoesNotExist:
            raise AttributeValue.DoesNotExist
        try:
            at = Attribute.objects.get_by_natural_key(*attribute_nk)
        except Attribute.DoesNotExist:
            raise AttributeValue.DoesNotExist
        return self.get(content_type=ct, object_id=owner.pk, attribute=at)


class ServiceQuerySet(managers.InheritanceQuerySetMixin, GetBySlugQuerySet):
    pass


class BaseServiceManager(models.Manager):
    use_for_related_fields = True

    def get_by_natural_key(self, ou_natural_key, slug):
        OU = get_ou_model()
        kwargs = {'slug': slug}
        if ou_natural_key:
            try:
                ou = OU.objects.get_by_natural_key(*ou_natural_key)
            except OU.DoesNotExist:
                raise self.model.DoesNotExist
            kwargs['ou'] = ou
        else:
            kwargs['ou__isnull'] = True
        return self.get(**kwargs)


class AttributeManager(managers.QueryManager.from_queryset(GetByNameQuerySet)):
    use_for_related_fields = False


ServiceManager = BaseServiceManager.from_queryset(ServiceQuerySet)
AttributeValueManager = models.Manager.from_queryset(AttributeValueQuerySet)
