# Bootstrap django-datetime-widget is a simple and clean widget for DateField,
# Timefiled and DateTimeField in Django framework. It is based on Bootstrap
# datetime picker, supports Bootstrap 2
#
# https://github.com/asaglimbeni/django-datetime-widget
#
# License: BSD
# Initial Author: Alfredo Saglimbeni

import json
import re
import uuid

from django.forms.widgets import DateTimeInput, DateInput, TimeInput
from django.utils.formats import get_language, get_format
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _

from gadjo.templatetags.gadjo import xstatic

DATE_FORMAT_JS_PY_MAPPING = {
    'P': '%p',
    'ss': '%S',
    'ii': '%M',
    'hh': '%H',
    'HH': '%I',
    'dd': '%d',
    'mm': '%m',
    'yy': '%y',
    'yyyy': '%Y',
}

DATE_FORMAT_TO_PYTHON_REGEX = re.compile(r'\b(' + '|'.join(DATE_FORMAT_JS_PY_MAPPING.keys()) + r')\b')


DATE_FORMAT_PY_JS_MAPPING = {
    '%M': 'ii',
    '%m': 'mm',
    '%I': 'HH',
    '%H': 'hh',
    '%d': 'dd',
    '%Y': 'yyyy',
    '%y': 'yy',
    '%p': 'P',
    '%S': 'ss'
}

DATE_FORMAT_TO_JS_REGEX = re.compile(r'(?<!\w)(' + '|'.join(DATE_FORMAT_PY_JS_MAPPING.keys()) + r')\b')


BOOTSTRAP_INPUT_TEMPLATE = """
      %(rendered_widget)s
      %(clear_button)s
      <span class="add-on"><i class="icon-th"></i></span>
      <span class="helptext">%(format_label)s %(format)s</span>
       <script type="text/javascript">
           $("#%(id)s").datetimepicker({%(options)s});
       </script>
       """

CLEAR_BTN_TEMPLATE = """<span class="add-on"><i class="icon-remove"></i></span>"""


class PickerWidgetMixin(object):
    class Media:
        css = {
            'all': ('css/datetimepicker.css',),
        }
        js = (
            xstatic('jquery', 'jquery.min.js'),
            xstatic('jquery_ui', 'jquery-ui.min.js'),
            'js/bootstrap-datetimepicker.js',
            'js/locales/bootstrap-datetimepicker.fr.js',
        )

    format_name = None
    glyphicon = None

    def __init__(self, attrs=None, options=None, usel10n=None):

        if attrs is None:
            attrs = {}

        self.options = options
        self.options['language'] = get_language().split('-')[0]

        # We're not doing localisation, get the Javascript date format provided by the user,
        # with a default, and convert it to a Python data format for later string parsing
        date_format = self.options['format']
        self.format = DATE_FORMAT_TO_PYTHON_REGEX.sub(
            lambda x: DATE_FORMAT_JS_PY_MAPPING[x.group()],
            date_format
            )

        super(PickerWidgetMixin, self).__init__(attrs, format=self.format)

    def get_format(self):
        format = get_format(self.format_name)[0]
        for py, js in DATE_FORMAT_PY_JS_MAPPING.iteritems():
            format = format.replace(py, js)
        return format

    def render(self, name, value, attrs=None):
        final_attrs = self.build_attrs(attrs)
        final_attrs['class'] = "controls input-append date"
        rendered_widget = super(PickerWidgetMixin, self).render(name, value, final_attrs)

        #if not set, autoclose have to be true.
        self.options.setdefault('autoclose', True)

        # Build javascript options out of python dictionary
        options_list = []
        for key, value in iter(self.options.items()):
            options_list.append("%s: %s" % (key, json.dumps(value)))

        js_options = ",\n".join(options_list)

        # Use provided id or generate hex to avoid collisions in document
        id = final_attrs.get('id', uuid.uuid4().hex)

        return mark_safe(BOOTSTRAP_INPUT_TEMPLATE % dict(
                    id=id,
                    rendered_widget=rendered_widget,
                    clear_button=CLEAR_BTN_TEMPLATE if self.options.get('clearBtn') else '',
                    glyphicon=self.glyphicon,
                    options=js_options,
                    format_label=_('Format:'),
                    format=self.options['format']
                    )
        )


class DateTimeWidget(PickerWidgetMixin, DateTimeInput):
    """
    DateTimeWidget is the corresponding widget for Datetime field, it renders both the date and time
    sections of the datetime picker.
    """

    format_name = 'DATETIME_INPUT_FORMATS'
    glyphicon = 'glyphicon-th'

    def __init__(self, attrs=None, options=None, usel10n=None):

        if options is None:
            options = {}

        # Set the default options to show only the datepicker object
        options['format'] = options.get('format', self.get_format())

        super(DateTimeWidget, self).__init__(attrs, options, usel10n)


class DateWidget(PickerWidgetMixin, DateInput):
    """
    DateWidget is the corresponding widget for Date field, it renders only the date section of
    datetime picker.
    """

    format_name = 'DATE_INPUT_FORMATS'
    glyphicon = 'glyphicon-calendar'

    def __init__(self, attrs=None, options=None, usel10n=None):

        if options is None:
            options = {}

        # Set the default options to show only the datepicker object
        options['startView'] = options.get('startView', 2)
        options['minView'] = options.get('minView', 2)
        options['format'] = options.get('format', self.get_format())

        super(DateWidget, self).__init__(attrs, options, usel10n)


class TimeWidget(PickerWidgetMixin, TimeInput):
    """
    TimeWidget is the corresponding widget for Time field, it renders only the time section of
    datetime picker.
    """

    format_name = 'TIME_INPUT_FORMATS'
    glyphicon = 'glyphicon-time'

    def __init__(self, attrs=None, options=None, usel10n=None):

        if options is None:
            options = {}

        # Set the default options to show only the timepicker object
        options['startView'] = options.get('startView', 1)
        options['minView'] = options.get('minView', 0)
        options['maxView'] = options.get('maxView', 1)
        options['format'] = options.get('format', self.get_format())

        super(TimeWidget, self).__init__(attrs, options, usel10n)
