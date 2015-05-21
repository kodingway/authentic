from django.utils.translation import ugettext_lazy as _
from django.utils.safestring import mark_safe
from django.contrib.auth.models import Group

import django_tables2 as tables

from django_rbac.utils import get_role_model, get_permission_model, \
    get_ou_model

from authentic2.compat import get_user_model


class UserTable(tables.Table):
    uuid = tables.Column()
    ou = tables.Column()
    username = tables.Column()
    email = tables.Column()

    class Meta:
        model = get_user_model()
        attrs = {'class': 'main', 'id': 'user-table'}
        fields = ('ou', 'uuid', 'username', 'email', 'first_name',
                  'last_name', 'is_active')
        empty_text = _('None')


class RoleMembersTable(UserTable):
    uuid = tables.Column()
    username = tables.TemplateColumn(
        '''{% load i18n %}
{% with perm=perms.custom_user.change_user %}
  <a rel="popup"
    {% if not perm %}
      class="disabled"
      title="{% trans "You are not permitted to edit users" %}"
    {% endif %}
    href="{% url "a2-manager-user-edit" pk=record.pk %}">
    {{ record.username }}
  </a>
{% endwith %}''',
        verbose_name=_('username'))
    email = tables.Column(verbose_name=mark_safe(_('Email')))
    direct = tables.BooleanColumn(verbose_name=_('Direct member'))

    class Meta:
        model = get_user_model()
        attrs = {'class': 'main', 'id': 'user-table'}
        fields = ('uuid', 'username', 'email', 'first_name', 'last_name',
                  'is_active')
        empty_text = _('None')


class RoleTable(tables.Table):
    name = tables.Column()
    ou = tables.Column()
    service = tables.Column()
    member_count = tables.Column(verbose_name=_('Direct members'))

    class Meta:
        models = get_role_model()
        attrs = {'class': 'main', 'id': 'role-table'}
        fields = ('name', 'ou', 'service', 'member_count')


class PermissionTable(tables.Table):
    operation = tables.Column()
    scope = tables.Column()
    target = tables.Column()

    class Meta:
        model = get_permission_model()
        attrs = {'class': 'main', 'id': 'role-table'}
        fields = ('operation', 'scope', 'target')


class OUTable(tables.Table):
    name = tables.Column()
    slug = tables.Column()
    default = tables.BooleanColumn()

    class Meta:
        model = get_ou_model()
        attrs = {'class': 'main', 'id': 'ou-table'}
        fields = ('name', 'slug')


class RoleChildrenTable(tables.Table):
    name = tables.Column(accessor='__unicode__', verbose_name=_('name'))
    ou = tables.Column()
    service = tables.Column(order_by='servicerole__service')
    direct = tables.BooleanColumn(verbose_name=_('Direct child'))

    class Meta:
        models = get_role_model()
        attrs = {'class': 'main', 'id': 'role-table'}
        fields = ('name', 'ou', 'service')
