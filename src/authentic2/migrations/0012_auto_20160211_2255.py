# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0011_auto_20160211_2253'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attributevalue',
            name='multiple',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
    ]
