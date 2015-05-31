from authentic2.utils import get_hex_uuid
from authentic2.decorators import GlobalCache
from django.conf import settings
from django.apps import apps

from . import constants

DEFAULT_MODELS = {
    constants.RBAC_OU_MODEL_SETTING: 'django_rbac.OrganizationalUnit',
    constants.RBAC_ROLE_PARENTING_MODEL_SETTING: 'django_rbac.RoleParenting',
    constants.RBAC_ROLE_MODEL_SETTING: 'django_rbac.Role',
    constants.RBAC_PERMISSION_MODEL_SETTING: 'django_rbac.Permission',
}

def get_swapped_model_name(setting):
    '''Return a model qualified name given a setting name containing the
       qualified name of the model, useful to retrieve swappable models
       name.
    '''
    if not hasattr(settings, setting):
        setattr(settings, setting, DEFAULT_MODELS[setting])
    return getattr(settings, setting)

def get_swapped_model(setting):
    '''Return a model given a setting name containing the qualified name
       of the model, useful to retrieve swappable models.
    '''
    app, model_name = get_swapped_model_name(setting).rsplit('.', 1)
    return apps.get_model(app, model_name)

def get_role_model_name():
    '''Returns the currently configured role model'''
    return get_swapped_model_name(constants.RBAC_ROLE_MODEL_SETTING)

def get_ou_model_name():
    '''Returns the currently configured organizational unit model'''
    return get_swapped_model_name(constants.RBAC_OU_MODEL_SETTING)

def get_role_parenting_model_name():
    '''Returns the currently configured role parenting model'''
    return get_swapped_model_name(constants.RBAC_ROLE_PARENTING_MODEL_SETTING)

def get_permission_model_name():
    '''Returns the currently configured permission model'''
    return get_swapped_model_name(constants.RBAC_PERMISSION_MODEL_SETTING)

def get_role_model():
    '''Returns the currently configured role model'''
    return get_swapped_model(constants.RBAC_ROLE_MODEL_SETTING)

def get_ou_model():
    '''Returns the currently configured organizational unit model'''
    return get_swapped_model(constants.RBAC_OU_MODEL_SETTING)

def get_role_parenting_model():
    '''Returns the currently configured role parenting model'''
    return get_swapped_model(constants.RBAC_ROLE_PARENTING_MODEL_SETTING)

def get_permission_model():
    '''Returns the currently configured permission model'''
    return get_swapped_model(constants.RBAC_PERMISSION_MODEL_SETTING)

def get_objects_with_permission(user, operation_slug, model):
    '''Returns a list of objects for which this user has the permission for the
       given operation.
    '''
    Permission = get_permission_model()
    OrganizationalUnit = get_ou_model()
    permissions = Permission.objects.for_user(user).filter(operation__slug=operation_slug)
    if permissions.filter(ou__isnull=True).exists():
        return model.objects.all()
    if model._meta.get_field('ou'):
        ous = OrganizationalUnit.objects.filter(scoped_permission=permissions)
        return model.objects.filer(ou=ous)
    else:
        return model.objects.none()

@GlobalCache
def get_operation(operation_tpl):
    from . import models
    operation, created = models.Operation.objects.get_or_create(
        slug=unicode(operation_tpl.slug),
        defaults={'name': unicode(operation_tpl.name)})
    return operation
