from django.utils.translation import ugettext as _
from django.core.exceptions import ValidationError
from django.forms import EmailField

from . import widgets

class EmailFieldWithValidation(EmailField):
    widget = widgets.EmailInputWithValidation

    def clean(self, value):
        if value and value[0] != value[1]:
            raise ValidationError(_('The two email fields didn\'t match.'))
        return super(EmailFieldWithValidation, self).clean(value[0])

