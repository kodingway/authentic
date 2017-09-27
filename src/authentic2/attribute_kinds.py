import re
import string
import datetime

from itertools import chain

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import ugettext_lazy as _, pgettext_lazy
from django.utils.functional import allow_lazy
from django.template.defaultfilters import capfirst

from rest_framework import serializers

from .decorators import to_iter
from .plugins import collect_from_plugins
from . import app_settings, widgets

capfirst = allow_lazy(capfirst, unicode)

DEFAULT_TITLE_CHOICES = (
    (pgettext_lazy('title', 'Mrs'), pgettext_lazy('title', 'Mrs')),
    (pgettext_lazy('title', 'Mr'), pgettext_lazy('title', 'Mr')),
)


@to_iter
def get_title_choices():
    return app_settings.A2_ATTRIBUTE_KIND_TITLE_CHOICES or DEFAULT_TITLE_CHOICES

validate_phone_number = RegexValidator('^\+?\d{,20}$', message=_('Phone number can start with a + '
                                                                 'an must contain only digits.'))


class PhoneNumberField(forms.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 30
        super(PhoneNumberField, self).__init__(*args, **kwargs)

    def clean(self, value):
        if value not in self.empty_values:
            value = re.sub('[-.\s]', '', value)
            validate_phone_number(value)
        return value


class PhoneNumberDRFField(serializers.CharField):
    default_validators = [validate_phone_number]


validate_fr_postcode = RegexValidator('^\d{5}$', message=_('The value must be a number'))


class FrPostcodeField(forms.CharField):
    def clean(self, value):
        value = super(FrPostcodeField, self).clean(value)
        if value not in self.empty_values:
            value = value.strip()
            validate_fr_postcode(value)
        return value


class FrPostcodeDRFField(serializers.CharField):
    default_validators = [validate_fr_postcode]


DEFAULT_ALLOW_BLANK = True
DEFAULT_MAX_LENGTH = 256

DEFAULT_ATTRIBUTE_KINDS = [
    {
        'label': _('string'),
        'name': 'string',
        'field_class': forms.CharField,
        'kwargs': {
            'max_length': DEFAULT_MAX_LENGTH,
        },
    },
    {
        'label': _('title'),
        'name': 'title',
        'field_class': forms.ChoiceField,
        'kwargs': {
            'choices': get_title_choices(),
            'widget': forms.RadioSelect,
        }
    },
    {
        'label': _('boolean'),
        'name': 'boolean',
        'field_class': forms.BooleanField,
        'serialize': lambda x: str(int(bool(x))),
        'deserialize': lambda x: bool(int(x)),
    },
    {
        'label': _('date'),
        'name': 'date',
        'field_class': forms.DateField,
        'kwargs': {
            'widget': widgets.DateWidget,
        },
        'serialize': lambda x: x.isoformat(),
        'deserialize': lambda x: x and datetime.datetime.strptime(x, '%Y-%m-%d').date(),
        'rest_framework_field_class': serializers.DateField,
    },
    {
        'label': _('french postcode'),
        'name': 'fr_postcode',
        'field_class': FrPostcodeField,
        'rest_framework_field_class': FrPostcodeDRFField,
    },
    {
        'label': _('phone number'),
        'name': 'phone_number',
        'field_class': PhoneNumberField,
        'rest_framework_field_class': PhoneNumberDRFField,
    },
]


def get_attribute_kinds():
    attribute_kinds = {}
    for attribute_kind in chain(DEFAULT_ATTRIBUTE_KINDS, app_settings.A2_ATTRIBUTE_KINDS):
        attribute_kinds[attribute_kind['name']] = attribute_kind
    for attribute_kind in chain(*collect_from_plugins('attribute_kinds')):
        attribute_kinds[attribute_kind['name']] = attribute_kind
    return attribute_kinds


@to_iter
def get_choices():
    '''Produce a choice list to use in form fields'''
    for d in get_attribute_kinds().itervalues():
        yield (d['name'], capfirst(d['label']))


def only_digits(value):
    return u''.join(x for x in value if x in string.digits)


def validate_lun(value):
    l = [(int(x) * (1 + i % 2)) for i, x in enumerate(reversed(value))]
    return sum(x - 9 if x > 10 else x for x in l) % 10 == 0


def validate_siret(value):
    RegexValidator(r'^( *[0-9] *){14}$', _('SIRET number must contain 14 digits'), 'coin')(value)
    value = only_digits(value)
    if not validate_lun(value) or not validate_lun(value[:9]):
        raise ValidationError(_('SIRET validation code does not match'))


class SIRETField(forms.CharField):
    default_validators = [validate_siret]

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
    d.setdefault('default', None)
    d.setdefault('serialize', lambda x: x)
    d.setdefault('deserialize', lambda x: x)
    rest_field_kwargs = d.setdefault('rest_framework_field_kwargs', {})
    if 'rest_framework_field_class' not in d:
        d['rest_framework_field_class'] = serializers.CharField
        rest_field_kwargs.setdefault('allow_blank', DEFAULT_ALLOW_BLANK)
        rest_field_kwargs.setdefault('max_length', DEFAULT_MAX_LENGTH)
    return d
