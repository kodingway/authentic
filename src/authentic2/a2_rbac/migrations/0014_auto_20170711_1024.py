# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0013_auto_20170629_0007'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='organizationalunit',
            options={'ordering': ('-default', 'name'), 'verbose_name': 'organizational unit', 'verbose_name_plural': 'organizational units'},
        ),
    ]
