# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_auth_oidc', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='oidcprovider',
            name='token_revocation_endpoint',
            field=models.URLField(max_length=128, null=True, verbose_name='token revocation endpoint', blank=True),
        ),
    ]
