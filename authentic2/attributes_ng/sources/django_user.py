from django.utils.translation import ugettext_lazy as _

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
    yield 'django_user_groups', User._meta.get_field_by_name('groups')[0].verbose_name + u' (django_user_groups)'
    yield 'django_user_group_names', User._meta.get_field_by_name('groups')[0].verbose_name + u' (django_user_group_names)'
    yield 'django_user_domain', _('User domain') + u' (django_user_domain)'
    yield 'django_user_identifier', _('User identifier') + u' (django_user_identifier)'

def get_dependencies(instance, ctx):
    return ('user',)

def get_attributes(instance, ctx):
    user = ctx.get('user')
    User = get_user_model()
    if not user or not isinstance(user, User):
        return ctx
    for field in User._meta.fields:
        ctx['django_user_' + str(field.name)] = getattr(user, field.name)
    for av in AttributeValue.objects.with_owner(user):
        ctx['django_user_' + str(av.attribute.name)] = av.to_python()
    ctx['django_user_groups'] = [group for group in user.groups.all()]
    ctx['django_user_group_names'] = [unicode(group) for group in user.groups.all()]
    ctx['django_user_domain'] = user.username.rsplit('@', 1)[-1] if '@' in user.username else ''
    return ctx
