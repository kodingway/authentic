# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attribute',
            name='kind',
            field=models.CharField(max_length=16, verbose_name='kind'),
            preserve_default=True,
        ),
    ]
