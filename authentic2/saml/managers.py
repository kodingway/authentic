import base64
import binascii
import datetime


from django.conf import settings
from django.db import models
from django.db.models.query import QuerySet
from django.dispatch import Signal
from django.utils.timezone import now
from django.utils.importlib import import_module


from model_utils import managers

from . import lasso_helper
from ..managers import GetBySlugQuerySet

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

class LibertyAssertionManager(models.Manager):
    def cleanup(self):
        # keep assertions 1 week
        expire = getattr(settings, 'SAML2_ASSERTION_EXPIRATION', 3600*24*7)
        before = now()-datetime.timedelta(seconds=expire)
        self.filter(creation__lt=before).delete()

class LibertyFederationManager(models.Manager):
    def cleanup(self):
        for federation in self.filter(user__isnull=True):
            results = federation_delete.send_robust(sender=federation)
            for callback, result in results:
                if not result:
                    return
            federation.delete()


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
