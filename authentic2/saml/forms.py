import urllib2

from django.forms import Form, CharField, SlugField, URLField, ValidationError
from django.utils.translation import ugettext_lazy as _

from .models import LibertyProvider

class AddLibertyProviderFromUrlForm(Form):
    name = CharField(max_length=140, label=_('Name'))
    slug = SlugField(max_length=140, label=_('Shortcut'),
            help_text=_("Internal nickname for the service provider"))
    url = URLField(label=_("Metadata's URL"))

    def clean(self):
        import pdb
        pdb.set_trace()
        cleaned_data = super(AddLibertyProviderFromUrlForm, self).clean()
        name = cleaned_data['name']
        slug = cleaned_data['slug']
        url = cleaned_data['url']
        try:
            content = urllib2.urlopen(url).read().decode('utf-8')
            liberty_provider = LibertyProvider(name=name,
                slug=slug, metadata=content)
            liberty_provider.full_clean(exclude=
                    ('entity_id', 'protocol_conformance'))
        except ValidationError, e:
            raise
        except Exception, e:
            raise ValidationError('unsupported error: %s' % e)
        self.instance = liberty_provider
        return cleaned_data

    def save(self):
        self.instance.save()
        return self.instance




