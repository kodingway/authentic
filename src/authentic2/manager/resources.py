from import_export.resources import ModelResource
from authentic2.compat import get_user_model

class UserResource(ModelResource):
    class Meta:
        model = get_user_model()
        exclude = ('password', 'user_permissions')
        widgets = {
                'groups': {
                    'field': 'name',
                }
        }
