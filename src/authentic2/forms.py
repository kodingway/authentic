from django import forms
from django.forms.models import modelform_factory as django_modelform_factory
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.exceptions import ValidationError

from authentic2.compat import get_user_model

from . import models, app_settings


class EmailChangeFormNoPassword(forms.Form):
    email = forms.EmailField(label=_('New email'))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(EmailChangeFormNoPassword, self).__init__(*args, **kwargs)

class EmailChangeForm(EmailChangeFormNoPassword):
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput)

    def clean_password(self):
        password = self.cleaned_data["password"]
        if not self.user.check_password(password):
            raise forms.ValidationError(
                _('Incorrect password.'),
                code='password_incorrect',
            )
        return password

class NextUrlFormMixin(forms.Form):
    next_url = forms.CharField(widget=forms.HiddenInput(), required=False)

    def __init__(self, *args, **kwargs):
        from .middleware import StoreRequestMiddleware

        next_url = kwargs.pop('next_url', None)
        request = StoreRequestMiddleware.get_request()
        if not next_url and request:
            next_url = request.GET.get(REDIRECT_FIELD_NAME)
        super(NextUrlFormMixin, self).__init__(*args, **kwargs)
        if next_url:
            self.fields['next_url'].initial = next_url

class BaseUserForm(forms.ModelForm):
    error_messages = {
        'duplicate_username': _("A user with that username already exists."),
    }

    def __init__(self, *args, **kwargs):
        self.attributes = models.Attribute.objects.all()
        initial = kwargs.setdefault('initial', {})
        if kwargs.get('instance'):
            instance = kwargs['instance']
            for av in models.AttributeValue.objects.with_owner(instance):
                if av.attribute.name in self.declared_fields:
                    if av.verified:
                        self.declared_fields[av.attribute.name].widget.attrs['readonly'] = 'readonly'
                    initial[av.attribute.name] = av.to_python()
        super(BaseUserForm, self).__init__(*args, **kwargs)

    def clean(self):
        # make sure verified fields are not modified
        for av in models.AttributeValue.objects.with_owner(
                self.instance).filter(verified=True):
            self.cleaned_data[av.attribute.name] = av.to_python()
        super(BaseUserForm, self).clean()

    def save_attributes(self):
        verified_attributes = {}
        for av in models.AttributeValue.objects.with_owner(
                self.instance).filter(verified=True):
            verified_attributes[av.attribute.name] = True

        for attribute in self.attributes:
            if attribute.name in self.fields and not attribute.name in verified_attributes:
                attribute.set_value(self.instance,
                        self.cleaned_data[attribute.name])

    def save(self, commit=True):
        result = super(BaseUserForm, self).save(commit=commit)
        if commit:
            self.save_attributes()
        else:
            old = self.save_m2m
            def save_m2m(*args, **kwargs):
                old(*args, **kwargs)
                self.save_attributes()
            self.save_m2m = save_m2m
        return result


def modelform_factory(model, **kwargs):
    '''Build a modelform for the given model,

       For the user model also add attribute based fields.
    '''
    form = kwargs.pop('form', None)
    fields = kwargs.get('fields') or []
    required = list(kwargs.pop('required', []) or [])
    d = {}
    # KV attributes are only supported for the user model currently
    modelform = None
    if issubclass(model, get_user_model()):
        if not form:
            form = BaseUserForm
        attributes = models.Attribute.objects.all()
        for attribute in attributes:
            if attribute.name not in fields:
                continue
            d[attribute.name] = attribute.get_form_field()
        for field in app_settings.A2_REQUIRED_FIELDS:
            if not field in required:
                required.append(field)
    if not form or not hasattr(form, 'Meta'):
        meta_d = {'model': model, 'fields': '__all__'}
        meta = type('Meta', (), meta_d)
        d['Meta'] = meta
    if not form:  # fallback
        form = forms.ModelForm
    modelform = None
    if required:
        def __init__(self, *args, **kwargs):
            super(modelform, self).__init__(*args, **kwargs)
            for field in required:
                if field in self.fields:
                    self.fields[field].required = True
        d['__init__'] = __init__
    modelform = type(model.__name__ + 'ModelForm', (form,), d)
    kwargs['form'] = modelform
    modelform.required_css_class = 'form-field-required'
    return django_modelform_factory(model, **kwargs)
