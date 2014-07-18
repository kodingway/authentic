from django.utils.translation import ugettext_lazy as _
from django import forms

from . import utils, fields

class RoleAddForm(forms.Form):
    name = forms.CharField(
            label=_('Role name'))

    def save(self):
        return utils.role_add(self.cleaned_data['name'])


class ChooseUserForm(forms.Form):
    user = fields.ChooseUserField(label=_('user'))


