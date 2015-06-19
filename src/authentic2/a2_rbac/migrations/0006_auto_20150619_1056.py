# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0005_auto_20150526_1406'),
    ]

    operations = [
        migrations.AddField(
            model_name='organizationalunit',
            name='email_is_unique',
            field=models.BooleanField(default=False, verbose_name='Email is unique'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='organizationalunit',
            name='username_is_unique',
            field=models.BooleanField(default=False, verbose_name='Username is unique'),
            preserve_default=True,
        ),
    ]
