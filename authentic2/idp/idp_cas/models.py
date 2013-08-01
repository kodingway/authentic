from datetime import timedelta

from django.db import models
from django.utils.timezone import now


class CasTicketManager(models.Manager):
    def clean_expired(self):
        '''
           Remove expired tickets.
        '''
        self.filter(expire__gte=now()).delete()

    def cleanup(self):
        # Keep them 4 minutes
        expire = getattr(settings, 'CAS_TICKET_EXPIRATION', 240)
        self.filter(when__lt=now()-timedelta(seconds=expire)).delete()


class CasTicket(models.Model):
    '''Session ticket with a CAS 1.0 or 2.0 consumer'''

    ticket_id  = models.CharField(max_length=64)
    renew   = models.BooleanField(default=False)
    validity   = models.BooleanField(default=False)
    service = models.CharField(max_length=256)
    user    = models.CharField(max_length=128,blank=True,null=True)
    creation = models.DateTimeField(auto_now_add=True)
    '''Duration length for the ticket as seconds'''
    expire = models.DateTimeField(blank=True, null=True)

    def valid(self):
        return self.validity and not self.expired()

    def expired(self):
        '''Check if the given CAS ticket has expired'''
        if self.expire:
            return now() >= self.expire
        else:
            return False
