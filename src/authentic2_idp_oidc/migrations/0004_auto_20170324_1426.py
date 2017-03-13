# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_oidc', '0003_auto_20170329_1259'),
    ]

    operations = [
        migrations.AlterField(
            model_name='oidccode',
            name='nonce',
            field=models.TextField(null=True, verbose_name='nonce'),
        ),
        migrations.AlterField(
            model_name='oidccode',
            name='state',
            field=models.TextField(null=True, verbose_name='state'),
        ),
    ]
