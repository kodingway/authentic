import string
import json

from itertools import chain

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import ugettext_lazy as _
from django.utils.functional import allow_lazy
from django.template.defaultfilters import capfirst

from .decorators import to_list
from . import app_settings

capfirst = allow_lazy(capfirst, unicode)


DEFAULT_ATTRIBUTE_KINDS = [
        {
          'label': _('string'),
          'name': 'string',
          'field_class': forms.CharField,
        },
]

def get_attribute_kinds():
    attribute_kinds = {}
    for attribute_kind in chain(DEFAULT_ATTRIBUTE_KINDS, app_settings.A2_ATTRIBUTE_KINDS):
        attribute_kinds[attribute_kind['name']] = attribute_kind
    return attribute_kinds

@to_list
def get_choices():
    '''Produce a choice list to use in form fields'''
    for d in get_attribute_kinds().itervalues():
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
    defn = get_attribute_kinds()[kind]
    if 'kwargs' in defn:
        kwargs.update(defn['kwargs'])
    return defn['field_class'](**kwargs)

def get_kind(kind):
    d = get_attribute_kinds()[kind]
    d.setdefault('serialize', json.dumps)
    d.setdefault('deserialize', json.loads)
    return d
