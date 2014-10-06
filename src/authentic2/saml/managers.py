import base64
import binascii
import datetime


from django.conf import settings
from django.db import models
from django.db.models.query import QuerySet
from django.dispatch import Signal
from django.utils.timezone import now
from django.utils.importlib import import_module
from django.contrib.contenttypes.models import ContentType


from model_utils import managers

from . import lasso_helper
from ..managers import GetBySlugQuerySet, GenericManager

federation_delete = Signal()

class SessionLinkedQuerySet(QuerySet):
    def cleanup(self):
        engine = import_module(settings.SESSION_ENGINE)
        store = engine.SessionStore()
        for o in self.all():
            key = o.django_session_key
            if not store.exists(key):
                o.delete()

SessionLinkedManager = managers.PassThroughManager \
        .for_queryset_class(SessionLinkedQuerySet)

class LibertyFederationManager(models.Manager):
    def cleanup(self):
        for federation in self.filter(user__isnull=True):
            results = federation_delete.send_robust(sender=federation)
            for callback, result in results:
                if not result:
                    return
            federation.delete()

    def get_by_natural_key(self, username, sp_slug, idp_slug):
        kwargs = {'user__username': username}
        if sp_slug:
            kwargs['sp__liberty_provider__slug'] = sp_slug
        if idp_slug:
            kwargs['idp__liberty_provider__slug'] = idp_slug
        return self.get(**kwargs)


class LibertyArtifactManager(models.Manager):
    def cleanup(self):
        expire = getattr(settings, 'SAML2_ARTIFACT_EXPIRATION', 600)
        before = now()-datetime.timedelta(seconds=expire)
        self.filter(creation__lt=before).delete()


class LibertyProviderQueryset(GetBySlugQuerySet):
    def by_artifact(self, artifact):
        '''Find a provider whose SHA-1 hash of its entityID is the 5-th to the
           25-th byte of the given artifact'''
        try:
            artifact = base64.b64decode(artifact)
        except:
            raise ValueError('artifact %r is not a base64 encoded value')
        entity_id_sha1 = artifact[4:24]
        entity_id_sha1 = binascii.hexlify(entity_id_sha1)
        return self.filter(entity_id_sha1=entity_id_sha1)

    def idp_enabled(self):
        return self.filter(identity_provider__enabled=True)

    def sp_enabled(self):
        return self.filter(service_provider__enabled=True)

    def with_federation(self, user):
        return self.filter(identity_provider__libertyfederation__user=user)

    def without_federation(self, user):
        return self.exclude(identity_provider__libertyfederation__user=user)

LibertyProviderManager = managers.PassThroughManager \
        .for_queryset_class(LibertyProviderQueryset)

class LibertySessionQuerySet(SessionLinkedQuerySet):
    def to_session_dump(self):
        sessions = self.values('provider_id',
                'session_index',
                'name_id_qualifier',
                'name_id_format',
                'name_id_content',
                'name_id_sp_name_qualifier')
        return lasso_helper.build_session_dump(sessions)

LibertySessionManager = managers.PassThroughManager \
        .for_queryset_class(LibertySessionQuerySet)

class GetByLibertyProviderManager(models.Manager):
    def get_by_natural_key(self, slug):
        from .models import LibertyProvider
        try:
            return self.get(liberty_provider__slug=slug)
        except self.model.DoesNotExist:
            try:
                liberty_provider = LibertyProvider.objects.get(slug=slug)
            except LibertyProvider.DoesNotExist:
                raise self.model.DoesNotExist
            return self.create(liberty_provider=liberty_provider)

class SAMLAttributeManager(GenericManager):
    def get_by_natural_key(self, ct_nk, provider_nk, name_format, name, friendly_name, attribute_name):
        from .models import SAMLAttribute
        try:
            ct = ContentType.objects.get_by_natural_key(*ct_nk)
        except ContentType.DoesNotExist:
            raise SAMLAttribute.DoesNotExist
        try:
            provider_class = ct.model_class()
            provider = provider_class.objects.get_by_natural_key(*provider_nk)
        except provider_class.DoesNotExist:
            raise SAMLAttribute.DoesNotExist
        return self.get(content_type=ct, object_id=provider.pk,
                name_format=name_format, name=name,
                friendly_name=friendly_name, attribute_name=attribute_name)
