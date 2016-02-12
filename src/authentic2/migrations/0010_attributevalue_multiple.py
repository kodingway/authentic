# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0009_auto_20160211_2247'),
    ]

    operations = [
        migrations.AddField(
            model_name='attributevalue',
            name='multiple',
            field=models.NullBooleanField(),
            preserve_default=True,
        ),
    ]
