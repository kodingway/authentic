from django.utils.translation import ugettext_lazy as _
from django.utils.safestring import mark_safe

import django_tables2 as tables

from authentic2.compat import get_user_model

class UserTable(tables.Table):
    username = tables.TemplateColumn(
        '<a rel="popup" href="{% url "a2-manager-user-edit" pk=record.pk %}">{{ record.username }}</a>',
        verbose_name=_('username'))
    email = tables.Column(verbose_name=mark_safe(_('Email')))

    class Meta:
        model = get_user_model()
        attrs = {'class': 'main', 'id': 'user-table'}
        fields = ('username', 'email', 'first_name', 'last_name',
                'is_active')
        empty_text = _('None')
