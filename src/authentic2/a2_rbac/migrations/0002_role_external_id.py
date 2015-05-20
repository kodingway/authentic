# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='role',
            name='external_id',
            field=models.TextField(db_index=True, verbose_name='external id', blank=True),
            preserve_default=True,
        ),
    ]
