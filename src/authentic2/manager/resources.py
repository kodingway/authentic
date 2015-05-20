from import_export.resources import ModelResource
from import_export.fields import Field
from import_export.widgets import Widget

from authentic2.compat import get_user_model
from authentic2.a2_rbac.models import Role


class UserResource(ModelResource):
    class Meta:
        model = get_user_model()
        exclude = ('password', 'user_permissions')
        widgets = {
            'groups': {
                'field': 'name',
            }
        }


class UserListWidget(Widget):
    def clean(self, value):
        raise NotImplementedError

    def render(self, value):
        return u', '.join(map(unicode, value.all()))


class RoleResource(ModelResource):
    members = Field(attribute='members', widget=UserListWidget())

    class Meta:
        model = Role
        fields = ('name', 'members')
