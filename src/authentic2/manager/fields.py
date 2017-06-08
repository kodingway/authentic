from django import forms

from . import widgets


class Select2Mixin(object):
    def __init__(self, **kwargs):
        if getattr(self.widget, 'queryset', None) is not None:
            kwargs['queryset'] = self.widget.queryset
        elif getattr(self.widget, 'model', None):
            kwargs['queryset'] = self.widget.model.objects.all()
        else:
            raise NotImplementedError
        assert kwargs['queryset'] is not None
        super(Select2Mixin, self).__init__(**kwargs)

    def __setattr__(self, key, value):
        if key == 'queryset':
            self.widget.queryset = value
        super(Select2Mixin, self).__setattr__(key, value)


class Select2ModelChoiceField(Select2Mixin, forms.ModelChoiceField):
    pass


class Select2ModelMultipleChoiceField(Select2Mixin, forms.ModelMultipleChoiceField):
    pass


for key in dir(widgets):
    cls = getattr(widgets, key)
    if not isinstance(cls, type):
        continue
    if issubclass(cls, widgets.ModelSelect2MultipleWidget):
        cls_name = key.replace('Widget', 'Field')
        vars()[cls_name] = type(cls_name, (Select2ModelMultipleChoiceField,), {
            'widget': cls,
        })
    elif issubclass(cls, widgets.ModelSelect2Widget):
        cls_name = key.replace('Widget', 'Field')
        vars()[cls_name] = type(cls_name, (Select2ModelChoiceField,), {
            'widget': cls,
        })
