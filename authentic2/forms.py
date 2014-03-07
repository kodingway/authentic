from django import forms
from django.contrib.auth import models as auth_models
from django.utils.translation import ugettext_lazy as _

from authentic2.compat import get_user_model

auth_models.User.USER_PROFILE = ('first_name', 'last_name', 'email')
User = get_user_model()
all_field_names = [field.name for field in User._meta.fields]
field_names = getattr(User, 'USER_PROFILE', all_field_names)


class UserProfileForm(forms.ModelForm):
    error_css_class = 'form-field-error'
    required_css_class = 'form-field-required'

    def __init__(self, *args, **kwargs):
        super(UserProfileForm, self).__init__(*args, **kwargs)
        for field in get_user_model().REQUIRED_FIELDS:
            if field in self.fields:
                self.fields[field].required = True


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
