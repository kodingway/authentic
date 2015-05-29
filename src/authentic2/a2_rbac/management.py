from django.utils.translation import ugettext as _
from django.utils.text import slugify
from django.contrib.contenttypes.models import ContentType
from django.db.transaction import atomic

from django_rbac.utils import get_role_model, get_permission_model, \
    get_ou_model, get_operation
from django_rbac.models import ADMIN_OP

from ..utils import get_fk_model


@atomic
def update_ou_admin_roles():
    '''Create general admin roles linked to all organizational units,
       they give general administrative rights to all mamanged content types
       scoped to the given organizational unit.
    '''
    OU = get_ou_model()
    Role = get_role_model()
    Permission = get_permission_model()
    admin_op = get_operation(ADMIN_OP)
    ou_all = OU.objects.all()
    ou_perms = Permission.objects.by_target_ct(OU).filter(
        ou__isnull=True,
        operation=admin_op,
        target_id__in=ou_all.values_list('id', flat=True))
    ou_role_qs = Role.objects.by_admin_scope_ct(Permission) \
        .filter(admin_scope_id__in=ou_perms.values_list('id', flat=True)) \
        .prefetch_related('admin_scope')
    ou_admin_roles = dict((r.admin_scope, r) for r in ou_role_qs)
    for ou in ou_all:
        if ou not in ou_admin_roles:
            ou_admin_roles[ou] = ou.get_admin_role()
    return ou_admin_roles

MANAGED_CT = {
    ('authentic2', 'service'): {
        'name': _('Manager of services'),
        'scoped_name': _('Services - {ou}'),
    },
    ('a2_rbac', 'role'): {
        'name': _('Manager of roles'),
        'scoped_name': _('Roles - {ou}'),
    },
    ('a2_rbac', 'organizationalunit'): {
        'name': _('Manager of organizational units'),
        'scoped_name': _('Organizational unit - {ou}'),
    },
    ('custom_user', 'user'): {
        'name': _('Manager of users'),
        'scoped_name': _('Users - {ou}'),
    },
}


@atomic
def update_content_types_roles(ou_admin_roles):
    '''Create general and scoped management roles for all managed content
       types.
    '''
    cts = ContentType.objects.all()
    OU = get_ou_model()
    ous = OU.objects.all()
    Role = get_role_model()

    for ct in cts:
        ct_tuple = (ct.app_label.lower(), ct.model.lower())
        if ct_tuple not in MANAGED_CT:
            continue
        # General admin role
        model_class = ct.model_class()
        name = MANAGED_CT[ct_tuple]['name']
        slug = '_a2-' + slugify(name)
        Role.objects.get_admin_role(instance=ct, name=name, slug=slug,
                                    update_name=True)
        ou_model = get_fk_model(model_class, 'ou')
        # do not create scoped admin roles if the model is not scopable
        if not ou_model:
            continue
        scoped_name = MANAGED_CT[ct_tuple]['scoped_name']
        for ou in ous:
            name = scoped_name.format(ou=ou)
            ou_slug = slug + '-' + ou.slug
            ou_ct_admin_role = Role.objects.get_admin_role(
                instance=ct,
                ou=ou,
                name=name,
                slug=ou_slug,
                update_name=True)
            ou_ct_admin_role.add_child(ou_admin_roles[ou])


def update_rbac():
    '''Create all automatic management roles.'''
    ou_admin_roles = update_ou_admin_roles()
    update_content_types_roles(ou_admin_roles)
