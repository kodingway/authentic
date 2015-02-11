import string
import json

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import ugettext_lazy as _
from django.template.defaultfilters import capfirst

from .decorators import to_list
from . import app_settings

@to_list
def get_choices():
    '''Produce a choice list to use in form fields'''
    for d in ATTRIBUTE_KINDS.itervalues():
        yield (d['name'], capfirst(d['label']))

def only_digits(value):
    return u''.join(x for x in value if x in string.digits)

def validate_lun(value):
    l = [(int(x)* (1+i%2)) for i, x in enumerate(reversed(value))]
    return sum(x-9 if x > 10 else x for x in l) % 10 == 0

def validate_siret(value):
    RegexValidator(r'^( *[0-9] *){14}$', 
            _('SIRET number must contain 14 digits'), 'coin')(value)
    value = only_digits(value)
    if not validate_lun(value) or not validate_lun(value[:9]):
        raise ValidationError(_('SIRET validation code does not match'))

class SIRETField(forms.CharField):
    default_validators = [ validate_siret ]

    def to_python(self, value):
        value = super(SIRETField, self).to_python(value)
        value = only_digits(value)
        return value

def contribute_to_form(attribute_descriptions, form):
    for attribute_description in attribute_descriptions:
        attribute_description.contribute_to_form(form)

def get_form_field(kind, **kwargs):
    defn = ATTRIBUTE_KINDS[kind]
    if 'kwargs' in defn:
        kwargs.update(defn['kwargs'])
    return defn['field_class'](**kwargs)

def get_kind(kind):
    d = ATTRIBUTE_KINDS[kind]
    d.setdefault('serialize', json.dumps)
    d.setdefault('deserialize', json.loads)
    return d

ATTRIBUTE_KINDS = [
        {
          'label': _('string'),
          'name': 'string',
          'field_class': forms.CharField,
        },
]
ATTRIBUTE_KINDS += app_settings.A2_ATTRIBUTE_KINDS
ATTRIBUTE_KINDS = dict((d['name'], d) for d in ATTRIBUTE_KINDS)
