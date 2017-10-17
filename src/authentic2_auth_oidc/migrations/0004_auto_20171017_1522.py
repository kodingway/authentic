# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_auth_oidc', '0003_oidcprovider_show'),
    ]

    operations = [
        migrations.AlterField(
            model_name='oidcprovider',
            name='strategy',
            field=models.CharField(max_length=32, verbose_name='strategy', choices=[(b'create', 'create'), (b'find-uuid', 'use sub to find existing user through UUID'), (b'none', 'none')]),
        ),
    ]
