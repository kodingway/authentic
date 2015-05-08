from django.utils.translation import ugettext_lazy as _

from ...models import Service
from authentic2.a2_rbac.models import Role

from ...decorators import to_list


@to_list
def get_instances(ctx):
    return [None]


@to_list
def get_attribute_names(instance, ctx):
    service = ctx.get('service')
    if not isinstance(service, Service):
        return
    names = []
    for service_role in Role.objects.filter(service=service) \
            .prefetch_related('attributes'):
        for service_role_attribute in service_role.attributes.all():
            if service_role_attribute.name in names:
                continue
            names.append(service_role_attribute.name)
    names.sort()
    for name in names:
        yield (name, u'%s (%s)' % (name, _('role attribute')))


def get_dependencies(instance, ctx):
    return ('user', 'service',)


def get_attributes(instance, ctx):
    user = ctx.get('user')
    service = ctx.get('service')
    if not user or not service:
        return
    ctx = ctx.copy()
    roles = Role.objects.filter(service=service) \
        .for_user(user).prefetch_related('attributes')
    for service_role in roles:
        for service_role_attribute in service_role.attributes.all():
            name = service_role_attribute.name
            value = service_role_attribute.value
            values = ctx.get(name, [])
            if not isinstance(values, (list, tuple, set)):
                values = [values]
            values = set(values)
            if value not in values:
                values.add(value)
            ctx[name] = values
    return ctx
