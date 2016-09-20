import urlparse
from datetime import timedelta

from django.db import models
from django.db.models import query
from django.utils.timezone import now


class TicketQuerySet(query.QuerySet):
    def clean_expired(self):
        '''Remove expired tickets'''
        self.filter(expire__gte=now()).delete()

    def cleanup(self):
        '''Delete old tickets'''
        qs = self.filter(expire__lt=now())
        qs |= self.filter(expire__isnull=True,
                creation__lt=now()-timedelta(seconds=300))
        qs.delete()


class ServiceQuerySet(query.QuerySet):
    def for_service(self, service):
        '''Find service with the longest match'''
        parsed = urlparse.urlparse(service)
        matches = []
        for match in self.filter(urls__contains=parsed.netloc):
            urls = match.get_urls()
            for url in urls:
                if service.startswith(url):
                    matches.append((len(url), match))
        if not matches:
            return None
        matches.sort()
        return matches[0][1]


ServiceManager = models.Manager.from_queryset(ServiceQuerySet)

TicketManager = models.Manager.from_queryset(TicketQuerySet)
