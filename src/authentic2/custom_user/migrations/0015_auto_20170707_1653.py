# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('custom_user', '0014_set_email_verified'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='user',
            options={'ordering': ('last_name', 'first_name', 'email', 'username'), 'verbose_name': 'user', 'verbose_name_plural': 'users', 'permissions': (('view_user', 'can see available users'),)},
        ),
    ]
