import urllib2
import xml.etree.ElementTree as ET
from authentic2.compat_lasso import lasso

from django.forms import Form, CharField, SlugField, URLField, ValidationError
from django.utils.translation import ugettext_lazy as _

from .models import (LibertyProvider, LibertyServiceProvider,
        LibertyIdentityProvider)

class AddLibertyProviderFromUrlForm(Form):
    name = CharField(max_length=140, label=_('Name'))
    slug = SlugField(max_length=140, label=_('Shortcut'),
            help_text=_("Internal nickname for the service provider"))
    url = URLField(label=_("Metadata's URL"))

    def clean(self):
        cleaned_data = super(AddLibertyProviderFromUrlForm, self).clean()
        name = cleaned_data.get('name')
        slug = cleaned_data.get('slug')
        url = cleaned_data.get('url')
        self.instance = None
        self.childs = []
        if name and slug and url:
            try:
                content = urllib2.urlopen(url).read().decode('utf-8')
                root = ET.fromstring(content)
                if root.tag != '{%s}EntityDescriptor' % lasso.SAML2_METADATA_HREF:
                    raise ValidationError(_('Invalid SAML metadata: %s') % _('missing EntityDescriptor tag'))
                is_sp = not root.find('{%s}SPSSODescriptor' % lasso.SAML2_METADATA_HREF) is None
                is_idp = not root.find('{%s}IDPSSODescriptor' % lasso.SAML2_METADATA_HREF) is None
                if not (is_sp or is_idp):
                    raise ValidationError(_('Invalid SAML metadata: %s') % _('missing IDPSSODescriptor or SPSSODescriptor tags'))
                liberty_provider = LibertyProvider(name=name,
                    slug=slug, metadata=content, metadata_url=url)
                liberty_provider.full_clean(exclude=
                        ('entity_id', 'protocol_conformance'))
                if is_sp:
                    self.childs.append(LibertyServiceProvider(
                        liberty_provider=liberty_provider,
                        enabled=True))
                if is_idp:
                    self.childs.append(LibertyIdentityProvider(
                        liberty_provider=liberty_provider,
                        enabled=True))
            except ValidationError, e:
                raise
            except Exception, e:
                raise ValidationError('unsupported error: %s' % e)
            self.instance = liberty_provider
        return cleaned_data

    def save(self):
        if not self.instance is None:
            self.instance.save()
            for child in self.childs:
                child.liberty_provider = self.instance
                child.save()
        return self.instance
