import django_tables2 as tables
from django.contrib.auth.models import User

class UserTable(tables.Table):
    class Meta:
        model = User
        attrs = {'class': 'main', 'id': 'user-table'}
        fields = ('username', 'email', 'first_name', 'last_name',
                'is_active')
