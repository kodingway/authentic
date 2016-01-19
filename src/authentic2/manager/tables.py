from django.utils.translation import ugettext_lazy as _
from django.utils.safestring import mark_safe
from django.contrib.auth.models import Group

import django_tables2 as tables
from django_tables2.utils import A

from django_rbac.utils import get_role_model, get_permission_model, \
    get_ou_model

from authentic2.models import Service
from authentic2.compat import get_user_model


class UserTable(tables.Table):
    link = tables.LinkColumn(
        viewname='a2-manager-user-edit',
        verbose_name=_('User'),
        accessor='get_full_name',
        order_by=('first_name', 'last_name', 'email', 'username'),
        kwargs={'pk': A('pk')})
    username = tables.Column()
    email = tables.Column()
    ou = tables.Column()

    class Meta:
        model = get_user_model()
        attrs = {'class': 'main', 'id': 'user-table'}
        fields = ('username', 'email', 'first_name',
                  'last_name', 'is_active', 'ou')
        sequence = ('link', '...')
        empty_text = _('None')
        order_by = ('first_name', 'last_name', 'email', 'username')


class RoleMembersTable(UserTable):
    direct = tables.BooleanColumn(verbose_name=_('Direct member'),
                                  orderable=False)

    class Meta(UserTable.Meta):
        pass


class RoleTable(tables.Table):
    name = tables.LinkColumn(viewname='a2-manager-role-members',
                             kwargs={'pk': A('pk')},
                             accessor='name', verbose_name=_('label'))
    ou = tables.Column()
    member_count = tables.Column(verbose_name=_('Member count'),
                                 orderable=False)

    class Meta:
        models = get_role_model()
        attrs = {'class': 'main', 'id': 'role-table'}
        fields = ('name', 'ou', 'member_count')


class PermissionTable(tables.Table):
    operation = tables.Column()
    scope = tables.Column()
    target = tables.Column()

    class Meta:
        model = get_permission_model()
        attrs = {'class': 'main', 'id': 'role-table'}
        fields = ('operation', 'scope', 'target')
        empty_text = _('None')


class OUTable(tables.Table):
    name = tables.Column(verbose_name=_('label'))
    default = tables.BooleanColumn()

    class Meta:
        model = get_ou_model()
        attrs = {'class': 'main', 'id': 'ou-table'}
        fields = ('name', 'default')
        empty_text = _('None')


class RoleChildrenTable(tables.Table):
    name = tables.LinkColumn(viewname='a2-manager-role-members',
                             kwargs={'pk': A('pk')},
                             accessor='name', verbose_name=_('name'))
    ou = tables.Column()
    service = tables.Column(order_by='servicerole__service')
    is_direct = tables.BooleanColumn(verbose_name=_('Direct child'))

    class Meta:
        models = get_role_model()
        attrs = {'class': 'main', 'id': 'role-table'}
        fields = ('name', 'ou', 'service')
        empty_text = _('None')


class OuUserRolesTable(tables.Table):
    name = tables.LinkColumn(viewname='a2-manager-role-members',
                             kwargs={'pk': A('pk')},
                             accessor='name', verbose_name=_('label'))
    via = tables.TemplateColumn(
        '''{% for rel in row.record.via %}{{ rel.child }} {% if not forloop.last %}, {% endif %}{% endfor %}''',
        verbose_name=_('Inherited from'), orderable=False)
    member = tables.TemplateColumn('''{% load i18n %}<input class="role-member{% if not row.record.member and row.record.via %} indeterminate{% endif %}" name='role-{{ row.record.pk }}' type='checkbox' {% if row.record.member %}checked{% endif %} {% if not row.record.has_perm %}disabled title="{% trans "You are not authorized to manage this role" %}"{% endif %}/>''',
                                  verbose_name=_('Member'), order_by=('member', 'via', 'name'))


    class Meta:
        models = get_role_model()
        attrs = {'class': 'main', 'id': 'role-table'}
        empty_text = _('None')
        order_by = ('name',)


class UserRolesTable(tables.Table):
    name = tables.LinkColumn(viewname='a2-manager-role-members',
                             kwargs={'pk': A('pk')},
                             accessor='name', verbose_name=_('label'))
    ou = tables.Column()
    via = tables.TemplateColumn(
        '''{% if not row.record.member %}{% for rel in row.record.child_relation.all %}{{ rel.child }} {% if not forloop.last %}, {% endif %}{% endfor %}{% endif %}''',
        verbose_name=_('Inherited from'))

    class Meta:
        models = get_role_model()
        attrs = {'class': 'main', 'id': 'role-table'}
        fields = ('name', 'ou')
        empty_text = _('None')
        order_by = ('name', 'ou')


class ServiceTable(tables.Table):
    ou = tables.Column()
    name = tables.Column()
    slug = tables.Column()

    class Meta:
        models = Service
        attrs = {'class': 'main', 'id': 'service-table'}
        empty_text = _('None')

class ServiceRolesTable(tables.Table):
    name = tables.Column(accessor='name', verbose_name=_('name'))

    class Meta:
        models = get_role_model()
        attrs = {'class': 'main', 'id': 'service-role-table'}
        fields = ('name',)
        empty_text = _('None')
