# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.RBAC_OU_MODEL),
        ('authentic2', '0004_service'),
    ]

    operations = [
        migrations.AddField(
            model_name='service',
            name='ou',
            field=models.ForeignKey(blank=True, to=settings.RBAC_OU_MODEL, null=True),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='service',
            unique_together=set([('slug', 'ou')]),
        ),
    ]
