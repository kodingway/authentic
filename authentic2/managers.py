from datetime import timedelta
import logging


from django.db import models
from django.db.models.query import QuerySet
from django.utils.timezone import now
from django.utils.http import urlquote
from django.conf import settings

from model_utils import managers

logger = logging.getLogger(__name__)

class DeletedUserManager(models.Manager):
    def delete_user(self, user):
        user.is_active = False
        user.save()
        self.create(user=user)

    def cleanup(self):
        '''Delete all deleted users for more than 10 minutes.'''
        not_after = now() - timedelta(seconds=600)
        for deleted_user in self.filter(creation__lte=not_after):
            user = deleted_user.user
            deleted_user.delete()
            user.delete()
            logger.info(u'deleted account %s' % user)

class AuthenticationEventManager(models.Manager):
    def cleanup(self):
        expire = getattr(settings, 'AUTHENTICATION_EVENT_EXPIRATION',
                3600*24*7)
        self.filter(when__lt=now()-timedelta(seconds=expire)).delete()

LOCAL_PROVIDER_URN = 'urn:oid:1.3.6.1.4.1.36560.1.1:local-provider'
LOCAL_USER_URN = 'urn:oid:1.3.6.1.4.1.36560.1.1:local-user'
LOCAL_SERVICE_URN = 'urn:oid:1.3.6.1.4.1.36560.1.1:local-service'


class FederatedIdQuerySet(QuerySet):
    def about_local_user(self, user):
        return self.filter(about=FederatedIdManager.local_user_id(user))

    def for_local_service(self, service):
        return self.filter(service=FederatedIdManager.local_service_id(service))

    def for_local_user_and_service(self, user, service):
        return self.filter(provider=LOCAL_PROVIDER_URN) \
                .about_local_user(user) \
                .for_service_model(service)

class FederatedIdManager(managers.PassThroughManager \
        .for_queryset_class(FederatedIdQuerySet)):

    @classmethod
    def local_user_id(cls, user):
        return '%s %s' % (LOCAL_USER_URN, urlquote(user.username))

    @classmethod
    def local_service_id(cls, service):
        model_id = '%s.%s' % (service._meta.app_label, service._meta.module_name)
        return '%s %s %s' % (LOCAL_SERVICE_URN, model_id, urlquote(service.pk))

    def get_or_create_for_local_user_and_service(self, user, service, id_format, id_value):
        return self.get_or_create(
                provider=LOCAL_PROVIDER_URN,
                about=self.local_user_id(user),
                service=self.local_service_id(service),
                defaults={
                    'id_format': id_format,
                    'id_value': id_value})

class AttributeValueQuerySet(QuerySet):
    pass

AttributeValueManager = managers.PassThroughManager \
        .for_queryset_class(AttributeValueQuerySet)
