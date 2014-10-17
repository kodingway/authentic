from django.forms.widgets import MultiWidget
from django.utils.translation import ugettext_lazy as _

try:
    from django.forms import EmailInput
except ImportError:
    from django.forms import TextInput as EmailInput



class WidgetWithValidation(MultiWidget):
    def __init__(self, widget_class, attrs=None):
        confirm_attrs = {'placeholder': _('Confirmation..')}
        if attrs:
            confirm_attrs.update(attrs)
        widgets = widget_class(attrs=attrs), widget_class(attrs=confirm_attrs)
        super(WidgetWithValidation, self).__init__(widgets, attrs=attrs);

    def decompress(self, value):
        if value and isinstance(value, (tuple, list)):
            return [value[0], '']
        return ['', '']

class EmailInputWithValidation(WidgetWithValidation):
    def __init__(self, attrs=None):
        super(EmailInputWithValidation, self).__init__(widget_class=EmailInput, attrs=attrs)
