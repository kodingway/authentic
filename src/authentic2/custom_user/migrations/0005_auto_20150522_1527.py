# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('custom_user', '0004_user_ou'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='ou',
            field=models.ForeignKey(verbose_name='organizational unit', blank=True, to=settings.RBAC_OU_MODEL, null=True),
            preserve_default=True,
        ),
    ]
