# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0007_auto_20150708_1337'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='organizationalunit',
            options={'ordering': ('default', 'name'), 'verbose_name': 'organizational unit', 'verbose_name_plural': 'organizational units'},
        ),
    ]
