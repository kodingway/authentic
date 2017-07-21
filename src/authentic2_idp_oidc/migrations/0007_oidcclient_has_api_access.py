# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_oidc', '0006_auto_20170720_1054'),
    ]

    operations = [
        migrations.AddField(
            model_name='oidcclient',
            name='has_api_access',
            field=models.BooleanField(default=False, verbose_name='has API access'),
        ),
    ]
