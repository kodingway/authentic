# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_oidc', '0005_authorization_mode'),
    ]

    operations = [
        migrations.AlterField(
            model_name='oidcclient',
            name='authorization_mode',
            field=models.PositiveIntegerField(default=1, verbose_name='authorization mode', choices=[(1, 'authorization by service'), (2, 'authorization by ou')]),
        ),
        migrations.AlterField(
            model_name='oidcclient',
            name='identifier_policy',
            field=models.PositiveIntegerField(default=2, verbose_name='identifier policy', choices=[(1, 'uuid'), (2, 'pairwise unreversible'), (4, 'pairwise reversible'), (3, 'email')]),
        ),
    ]
