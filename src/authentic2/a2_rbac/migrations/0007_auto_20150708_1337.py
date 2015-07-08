# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0006_auto_20150619_1056'),
    ]

    operations = [
        migrations.AlterField(
            model_name='role',
            name='permissions',
            field=models.ManyToManyField(related_name='roles', to=settings.RBAC_PERMISSION_MODEL, blank=True),
            preserve_default=True,
        ),
    ]
