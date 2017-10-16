# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_auth_oidc', '0002_oidcprovider_token_revocation_endpoint'),
    ]

    operations = [
        migrations.AddField(
            model_name='oidcprovider',
            name='show',
            field=models.BooleanField(default=True, verbose_name='show on login page'),
        ),
    ]
