# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0013_delete_model_service_proxy2'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ticket',
            name='service_url',
            field=models.TextField(default=b'', verbose_name='service URL', blank=True),
            preserve_default=True,
        ),
    ]
