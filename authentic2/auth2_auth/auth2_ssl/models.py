from django.db import models
from django.conf import settings

from . import util

class ClientCertificate(models.Model):
    serial = models.CharField(max_length=255, blank=True)
    subject_dn = models.CharField(max_length=255)
    issuer_dn = models.CharField(max_length=255)
    cert = models.TextField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    def __unicode__(self):
        return self.subject_dn

    def explode_subject_dn(self):
        return util.explode_dn(self.subject_dn)

    def explode_issuer_dn(self):
        return util.explode_dn(self.issuer_dn)

