from django.utils.translation import ugettext_lazy as _
from django import forms

from authentic2.compat import get_user_model

from . import utils, fields

class RoleAddForm(forms.Form):
    name = forms.CharField(
            label=_('Role name'))

    def save(self):
        return utils.role_add(self.cleaned_data['name'])


class ChooseUserForm(forms.Form):
    ref = fields.ChooseUserField(label=_('user'))


class UserEditForm(forms.ModelForm):
    groups = fields.GroupsField(required=False)

    class Meta:
        model = get_user_model()
        fields = [ 'username', 'first_name', 'last_name', 'email', 'groups']

