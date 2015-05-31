from django.utils.translation import ugettext as _
from django.utils.text import slugify
from django.contrib.contenttypes.models import ContentType

from django_rbac.utils import get_role_model, get_ou_model

from ..utils import get_fk_model


def update_ou_admin_roles(ou):
    Role = get_role_model()
    admin_role = ou.get_admin_role()

    for key in MANAGED_CT:
        ct = ContentType.objects.get_by_natural_key(key[0], key[1])
        model_class = ct.model_class()
        ou_model = get_fk_model(model_class, 'ou')
        # do not create scoped admin roles if the model is not scopable
        if not ou_model:
            continue
        name = MANAGED_CT[key]['name']
        slug = '_a2-' + slugify(name)
        scoped_name = MANAGED_CT[key]['scoped_name']
        name = scoped_name.format(ou=ou)
        ou_slug = slug + '-' + ou.slug
        ou_ct_admin_role = Role.objects.get_admin_role(
            instance=ct,
            ou=ou,
            name=name,
            slug=ou_slug,
            update_slug=True,
            update_name=True)
        ou_ct_admin_role.add_child(admin_role)


def update_ous_admin_roles():
    '''Create general admin roles linked to all organizational units,
       they give general administrative rights to all mamanged content types
       scoped to the given organizational unit.
    '''
    OU = get_ou_model()
    ou_all = OU.objects.all()
    ou_ids = ou_all.values_list('id', flat=True)
    ou_ids_with_perm = Permission.objects.filter(operation__slug='admin',
        target_ct=ContentType.objects.get_for_model(OU)) \
        .values_list('target_id', flat=True)

    for ou in OU.objects.filter(id__in=set(ou_ids)-set(ou_ids_with_perm)):
        update_ou_admin_roles(ou)
        print 'Administrative roles of', ou, 'updated.'

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


def update_content_types_roles():
    '''Create general and scoped management roles for all managed content
       types.
    '''
    cts = ContentType.objects.all()
    Role = get_role_model()

    for ct in cts:
        ct_tuple = (ct.app_label.lower(), ct.model.lower())
        if ct_tuple not in MANAGED_CT:
            continue
        # General admin role
        name = MANAGED_CT[ct_tuple]['name']
        slug = '_a2-' + slugify(name)
        Role.objects.get_admin_role(instance=ct, name=name, slug=slug,
                                    update_name=True)
