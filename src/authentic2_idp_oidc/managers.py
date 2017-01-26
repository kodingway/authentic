from django.db.models import Manager
from django.utils.timezone import now


class OIDCExpiredManager(Manager):
    def cleanup(self, tstamp=None):
        tstamp = tstamp or now()
        self.filter(expired__lt=tstamp).delete()
