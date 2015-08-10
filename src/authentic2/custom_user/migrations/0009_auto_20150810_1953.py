# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('custom_user', '0008_auto_20150617_1606'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='user',
            options={'ordering': ('first_name', 'last_name', 'email', 'username'), 'verbose_name': 'user', 'verbose_name_plural': 'users', 'permissions': (('view_user', 'can see available users'),)},
        ),
    ]
