# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0004_auto_20150523_0028'),
    ]

    operations = [
        migrations.AlterField(
            model_name='role',
            name='service',
            field=models.ForeignKey(related_name='roles', verbose_name='service', blank=True, to='authentic2.Service', null=True),
            preserve_default=True,
        ),
    ]
