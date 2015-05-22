# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0003_partial_unique_index_on_name_and_slug'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='organizationalunit',
            options={'ordering': ('name',), 'verbose_name': 'organizational unit', 'verbose_name_plural': 'organizational units'},
        ),
        migrations.AlterUniqueTogether(
            name='role',
            unique_together=set([]),
        ),
    ]
