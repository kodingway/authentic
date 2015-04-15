# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('authentic2_idp_cas', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ticket',
            name='user',
            field=models.ForeignKey(blank=True, to=settings.AUTH_USER_MODEL, max_length=128, null=True, verbose_name='user'),
            preserve_default=True,
        ),
    ]
