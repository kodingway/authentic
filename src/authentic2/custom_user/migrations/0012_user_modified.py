# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import datetime
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('custom_user', '0011_manual_attribute_values_for_name_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='modified',
            field=models.DateTimeField(default=datetime.datetime(2017, 3, 13, 14, 41, 7, 593150, tzinfo=utc), auto_now=True, verbose_name='Last modification time', db_index=True),
            preserve_default=False,
        ),
    ]
