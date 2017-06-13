# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0018_auto_20170524_0842'),
    ]

    operations = [
        migrations.AddField(
            model_name='attribute',
            name='searchable',
            field=models.BooleanField(default=False, verbose_name='searchable'),
        ),
        migrations.AlterField(
            model_name='attributevalue',
            name='content',
            field=models.TextField(verbose_name='content', db_index=True),
        ),
        migrations.AlterField(
            model_name='attributevalue',
            name='object_id',
            field=models.PositiveIntegerField(verbose_name='object identifier', db_index=True),
        ),
    ]
