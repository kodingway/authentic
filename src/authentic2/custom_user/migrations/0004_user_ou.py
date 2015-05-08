# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.RBAC_OU_MODEL),
        ('custom_user', '0003_auto_20150504_1410'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='ou',
            field=models.ForeignKey(blank=True, to=settings.RBAC_OU_MODEL, null=True),
            preserve_default=True,
        ),
    ]
