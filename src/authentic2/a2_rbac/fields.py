from django.db.models import NullBooleanField
from django import forms

class UniqueBooleanField(NullBooleanField):
    '''BooleanField allowing only one True value in the table, and preventing
       problems with multiple False values by implicitely converting them to
       None.'''
    def __init__(self, *args, **kwargs):
        kwargs['unique'] = True
        kwargs['blank'] = True
        kwargs['null'] = True
        kwargs['default'] = False
        super(NullBooleanField, self).__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super(NullBooleanField, self).deconstruct()
        del kwargs['null']
        del kwargs['blank']
        del kwargs['unique']
        del kwargs['default']
        return name, path, args, kwargs

    def to_python(self, value):
        value = super(UniqueBooleanField, self).to_python(value)
        if value is None:
            return False
        return value

    def get_prep_value(self, value):
        value = super(UniqueBooleanField, self).get_prep_value(value)
        if value is False:
            return None
        return value

    def formfield(self, **kwargs):
        # Unlike most fields, BooleanField figures out include_blank from
        # self.null instead of self.blank.
        if self.choices:
            include_blank = False
            defaults = {'choices': self.get_choices(include_blank=include_blank)}
        else:
            defaults = {'form_class': forms.BooleanField}
        defaults.update(kwargs)
        return super(NullBooleanField, self).formfield(**defaults)
