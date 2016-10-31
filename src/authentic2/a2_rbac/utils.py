from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django_rbac.models import VIEW_OP

from django_rbac import utils as rbac_utils

from . import models


def get_default_ou():
    try:
        return models.OrganizationalUnit.objects.get(default=True)
    except models.OrganizationalUnit.DoesNotExist:
        return None


def get_view_user_perm(ou=None):
    User = get_user_model()
    Permission = rbac_utils.get_permission_model()
    view_user_perm, created = Permission.objects.get_or_create(
        operation=rbac_utils.get_operation(VIEW_OP),
        target_ct=ContentType.objects.get_for_model(ContentType),
        target_id=ContentType.objects.get_for_model(User).pk,
        ou__isnull=ou is None, ou=ou)
    return view_user_perm


def get_view_ou_perm(ou=None):
    if ou:
        Permission = rbac_utils.get_permission_model()
        view_ou_perm, created = Permission.objects.get_or_create(
            operation=rbac_utils.get_operation(VIEW_OP),
            target_ct=ContentType.objects.get_for_model(ou),
            target_id=ou.pk,
            ou__isnull=True)
    else:
        OU = rbac_utils.get_ou_model()
        Permission = rbac_utils.get_permission_model()
        view_ou_perm, created = Permission.objects.get_or_create(
            operation=rbac_utils.get_operation(VIEW_OP),
            target_ct=ContentType.objects.get_for_model(ContentType),
            target_id=ContentType.objects.get_for_model(OU).pk,
            ou__isnull=True)
    return view_ou_perm
