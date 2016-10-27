import xml.etree.ElementTree as ET

import requests

from authentic2.compat_lasso import lasso

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _

from .models import LibertyProvider, LibertyServiceProvider

from authentic2.a2_rbac.utils import get_default_ou

from django_rbac.utils import get_ou_model


class AddLibertyProviderFromUrlForm(forms.Form):
    name = forms.CharField(max_length=140, label=_('Name'))
    slug = forms.SlugField(max_length=140, label=_('Shortcut'),
                           help_text=_("Internal nickname for the service provider"))
    url = forms.URLField(label=_("Metadata's URL"))
    ou = forms.ModelChoiceField(queryset=get_ou_model().objects, initial=get_default_ou,
                                label=_('Organizational unit'))

    def clean(self):
        cleaned_data = super(AddLibertyProviderFromUrlForm, self).clean()
        name = cleaned_data.get('name')
        slug = cleaned_data.get('slug')
        url = cleaned_data.get('url')
        ou = cleaned_data.get('ou')
        self.instance = None
        self.childs = []
        if name and slug and url:
            try:
                response = requests.get(url)
                response.raise_for_status()
                content = response.content
            except requests.RequestException, e:
                raise ValidationError(_('Retrieval of %(url)s failed: %(exception)s') % {
                    'url': url,
                    'exception': e
                })
            root = ET.fromstring(content)
            if root.tag != '{%s}EntityDescriptor' % lasso.SAML2_METADATA_HREF:
                raise ValidationError(_('Invalid SAML metadata: %s')
                                      % _('missing EntityDescriptor tag'))
            is_sp = not root.find('{%s}SPSSODescriptor' % lasso.SAML2_METADATA_HREF) is None
            if not is_sp:
                raise ValidationError(_('Invalid SAML metadata: %s')
                                      % _('missing SPSSODescriptor tags'))
            liberty_provider = LibertyProvider(name=name, slug=slug, metadata=content,
                                               metadata_url=url, ou=ou)
            liberty_provider.full_clean(exclude=('entity_id', 'protocol_conformance'))
            self.childs.append(LibertyServiceProvider(
                liberty_provider=liberty_provider,
                enabled=True))
            self.instance = liberty_provider
        return cleaned_data

    def save(self):
        if not self.instance is None:
            self.instance.save()
            for child in self.childs:
                child.liberty_provider = self.instance
                child.save()
        return self.instance
