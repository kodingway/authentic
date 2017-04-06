from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.utils.timezone import now
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

from authentic2.models import LogoutUrlAbstract, Service
from authentic2 import compat
from authentic2.utils import check_session_key

from . import managers, utils, constants

url_validator = URLValidator(schemes=['http', 'https', 'ftp', 'ftps', 'imap', 'imaps', 'sieve', 'smtp', 'smtps', 'ssh'])

class Service(LogoutUrlAbstract, Service):
    urls = models.TextField(max_length=128,
            verbose_name=_('urls'))
    identifier_attribute = models.CharField(max_length=64,
            verbose_name=_('attribute name'), blank=False)
    proxy = models.ManyToManyField('self',
            blank=True,
            verbose_name=_('proxy'),
            help_text=_('services who can request proxy tickets for this service'))

    objects = managers.ServiceManager()

    def clean(self):
        '''Check urls is a space separated list of urls and normalize it'''
        super(Service, self).clean()
        urls = self.urls.split(' ')
        for url in urls:
            try:
                url_validator(url)
            except ValidationError:
                raise ValidationError(_('%s is an invalid URL') % url)
        self.urls = u' '.join(urls)

    def match_service(self, service_url):
        '''Verify that this service match an URL'''
        for url in self.urls.split():
            if service_url.startswith(url):
                return True
        return False

    def get_urls(self):
        '''List or url for matching requesting services'''
        return list(map(None, self.urls.split()))

    def get_wanted_attributes(self):
        '''Compute wanted attributes for this service'''
        wanted = set([self.identifier_attribute])
        for attribute in self.attribute_set.all():
            wanted.add(attribute.attribute_name)
        return list(wanted)

    def __unicode__(self):
        return self.name

    class Meta:
        verbose_name = _('service')
        verbose_name_plural = _('services')


class Attribute(models.Model):
    service = models.ForeignKey(Service, verbose_name=_('service'))
    slug    = models.SlugField(verbose_name=_('slug'))
    attribute_name = models.CharField(max_length=64,
        verbose_name=_('attribute name'), blank=False)
    enabled = models.BooleanField(
            verbose_name=_('enabled'),
            default=True)

    def __unicode__(self):
        return u'%s <- %s' % (self.slug, self.attribute_name)

    class Meta:
        verbose_name = _('CAS attribute')
        verbose_name_plural = _('CAS attributes')
        unique_together = (('service', 'slug', 'attribute_name',),)

def make_uuid():
    return utils.make_id(constants.SERVICE_TICKET_PREFIX)

class Ticket(models.Model):
    '''Session ticket with a CAS 1.0 or 2.0 consumer'''

    ticket_id   = models.CharField(max_length=64,
                    verbose_name=_('ticket id'),
                    unique=True,
                    default=make_uuid)
    renew       = models.BooleanField(default=False,
            verbose_name=_('fresh authentication'))
    validity    = models.BooleanField(default=False,
            verbose_name=_('valid'))
    service     = models.ForeignKey(Service, verbose_name=_('service'))
    service_url = models.TextField(verbose_name=_('service URL'), blank=True, default='')
    user        = models.ForeignKey(compat.user_model_label, max_length=128,
            blank=True, null=True, verbose_name=_('user'))
    creation    = models.DateTimeField(auto_now_add=True,
            verbose_name=_('creation'))
    expire      = models.DateTimeField(
            verbose_name=_('expire'), blank=True, null=True)
    session_key = models.CharField(max_length=64, db_index=True, blank=True,
            verbose_name=_('django session key'), default='')
    proxies = models.TextField(
            verbose_name=_('proxies'), blank=True, default='')

    objects = managers.TicketManager()

    def __unicode__(self):
        return self.ticket_id

    def valid(self):
        return self.validity and not self.expired() and self.session_exists()

    def session_exists(self):
        '''Verify if the session linked to this ticket is still active'''
        if self.session_key:
            return check_session_key(self.session_key)
        else:
            return True

    def expired(self):
        '''Check if the given ticket has expired'''
        if self.expire:
            return now() >= self.expire
        else:
            return False

