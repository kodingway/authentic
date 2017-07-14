from django.utils.translation import ugettext_lazy as _

from django_rbac.utils import get_role_model

from ...models import Attribute, AttributeValue

from ...decorators import to_list
from ...compat import get_user_model


@to_list
def get_instances(ctx):
    '''
    Retrieve instances from settings
    '''
    return [None]


@to_list
def get_attribute_names(instance, ctx):
    User = get_user_model()
    for field in User._meta.fields:
        name = 'django_user_' + str(field.name)
        description = field.verbose_name + u' (%s)' % name
        yield name, description
    for attribute in Attribute.objects.all():
        name = 'django_user_' + str(attribute.name)
        description = attribute.label + u' (%s)' % name
        yield name, description
    group_label = User._meta.get_field_by_name('groups')[0].verbose_name
    yield 'django_user_groups', group_label + u' (django_user_groups)'
    yield 'django_user_group_names', group_label + u' (django_user_group_names)'
    yield 'django_user_domain', _('User domain') + u' (django_user_domain)'
    yield 'django_user_identifier', _('User identifier') + u' (django_user_identifier)'
    yield 'django_user_full_name', _('Full name') + u' (django_user_full_name)'
    yield 'a2_role_slugs', _('Role slugs')
    yield 'a2_role_names', _('Role names')
    yield 'a2_role_uuids', _('Role UUIDs')
    yield 'a2_service_ou_role_slugs', _('Role slugs from same organizational unit as the service')
    yield 'a2_service_ou_role_names', _('Role names from same organizational unit as the service')
    yield 'a2_service_ou_role_uuids', _('Role uuids from same organizational unit as the service')


def get_dependencies(instance, ctx):
    return ('user',)


def get_attributes(instance, ctx):
    user = ctx.get('user')
    User = get_user_model()
    if not user or not isinstance(user, User):
        return ctx
    for field in User._meta.fields:
        value = getattr(user, field.name)
        if value is None:
            continue
        ctx['django_user_' + str(field.name)] = getattr(user, field.name)
    for av in AttributeValue.objects.with_owner(user):
        ctx['django_user_' + str(av.attribute.name)] = av.to_python()
        ctx['django_user_' + str(av.attribute.name) + ':verified'] = av.verified
    ctx['django_user_groups'] = [group for group in user.groups.all()]
    ctx['django_user_group_names'] = [unicode(group) for group in user.groups.all()]
    if user.username:
        splitted = user.username.rsplit('@', 1)
        ctx['django_user_domain'] = splitted[1] if '@' in user.username else ''
        ctx['django_user_identifier'] = splitted[0] if '@' in user.username else ''
    ctx['django_user_full_name'] = user.get_full_name()
    Role = get_role_model()
    roles = Role.objects.for_user(user)
    ctx['a2_role_slugs'] = roles.values_list('slug', flat=True)
    ctx['a2_role_names'] = roles.values_list('name', flat=True)
    ctx['a2_role_uuids'] = roles.values_list('uuid', flat=True)
    if 'service' in ctx and getattr(ctx['service'], 'ou', None):
        ou = ctx['service'].ou
        ctx['a2_service_ou_role_slugs'] = roles.filter(ou=ou).values_list('slug', flat=True)
        ctx['a2_service_ou_role_names'] = roles.filter(ou=ou).values_list('name', flat=True)
        ctx['a2_service_ou_role_uuids'] = roles.filter(ou=ou).values_list('uuid', flat=True)
    return ctx
