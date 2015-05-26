# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('attribute_aggregator', '0002_auto_20150409_1840'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attributelist',
            name='attributes',
            field=models.ManyToManyField(to='attribute_aggregator.AttributeItem', verbose_name='Attributes', blank=True),
        ),
        migrations.AlterField(
            model_name='useraliasinsource',
            name='user',
            field=models.ForeignKey(verbose_name='user', to=settings.AUTH_USER_MODEL),
        ),
    ]
