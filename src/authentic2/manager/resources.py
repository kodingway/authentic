from import_export.resources import ModelResource
from import_export.fields import Field
from import_export.widgets import Widget

from authentic2.compat import get_user_model
from authentic2.a2_rbac.models import Role


class ListWidget(Widget):
    def clean(self, value):
        raise NotImplementedError

    def render(self, value):
        return u', '.join(map(unicode, value.all()))


class UserResource(ModelResource):
    roles = Field(attribute='roles_and_parents', widget=ListWidget())

    class Meta:
        model = get_user_model()
        exclude = ('password', 'user_permissions', 'is_staff',
                   'is_superuser', 'groups')
        export_order = ('ou', 'uuid', 'id', 'username', 'email',
                        'first_name', 'last_name', 'last_login',
                        'date_joined', 'roles')
        widgets = {
            'roles': {
                'field': 'name',
            },
            'ou': {
                'field': 'name',
            }
        }


class RoleResource(ModelResource):
    members = Field(attribute='members', widget=ListWidget())

    class Meta:
        model = Role
        fields = ('name', 'slug', 'members')
        export_order = fields
