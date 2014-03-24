from django import forms
from django.contrib.auth import models as auth_models
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import ugettext_lazy as _

from authentic2.compat import get_user_model

from . import models

auth_models.User.USER_PROFILE = ('first_name', 'last_name', 'email')
User = get_user_model()
all_field_names = [field.name for field in User._meta.fields]
field_names = getattr(User, 'USER_PROFILE', all_field_names)

__USER_FORM_CLASS = None

class UserAttributeFormMixin(object):
    def __init__(self, *args, **kwargs):
        super(UserAttributeFormMixin, self).__init__(*args, **kwargs)
        self.attributes = self.get_attributes()
        initial = {}
        if 'instance' in kwargs:
            content_type = ContentType.objects.get_for_model(self.instance)
            for av in models.AttributeValue.objects.filter(
                    content_type=content_type,
                    object_id=self.instance.pk):
                initial[av.attribute.name] = av.to_python()
        for attribute in self.attributes:
            iv = initial.get(attribute.name)
            attribute.contribute_to_form(self, initial=iv)

    def get_attributes(self):
        return models.Attribute.objects.all()

    def save_attributes(self):
        for attribute in self.attributes:
            attribute.set_value(self.instance,
                    self.cleaned_data[attribute.name])

    def save(self, commit=True):
        result = super(UserAttributeFormMixin, self).save(commit=commit)
        if commit:
            self.save_attributes()
        else:
            old = self.save_m2m
            def save_m2m(*args, **kwargs):
                old(*args, **kwargs)
                self.save_attributes()
            self.save_m2m = save_m2m
        return result

class UserProfileForm(UserAttributeFormMixin, forms.ModelForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    def __init__(self, *args, **kwargs):
        super(UserProfileForm, self).__init__(*args, **kwargs)
        for field in get_user_model().REQUIRED_FIELDS:
            if field in self.fields:
                self.fields[field].required = True

    def get_attributes(self):
        qs = super(UserProfileForm, self).get_attributes()
        qs = qs.filter(user_visible=True, user_editable=True)
        return qs

    class Meta:
        model = User
        fields = [ field_name
                for field_name in field_names
                if field_name in all_field_names
                    and field_name != model.USERNAME_FIELD
                    and field_name != 'email' ]

class EmailChangeForm(forms.Form):
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput)
    email = forms.EmailField(label=_('New email'))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(EmailChangeForm, self).__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data["password"]
        if not self.user.check_password(password):
            raise forms.ValidationError(
                _('Incorrect password.'),
                code='password_incorrect',
            )
        return password

from django import forms
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.contrib.auth.models import Group
from . import compat

class GroupAdminForm(forms.ModelForm):
    users = forms.ModelMultipleChoiceField(
            queryset=compat.get_user_model().objects.all(),
            widget=FilteredSelectMultiple(
                verbose_name=_('users'),
                is_stacked=False),
            required=False)

    class Meta:
        model = Group

    def __init__(self, *args, **kwargs):
        super(GroupAdminForm, self).__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields['users'].initial = self.instance.user_set.all()

    def save(self, commit=True):
        group = super(GroupAdminForm, self).save(commit=False)

        if commit:
            group.save()
        if group.pk:
            group.users = self.cleaned_data['users']
            self.save_m2m()
        return group
