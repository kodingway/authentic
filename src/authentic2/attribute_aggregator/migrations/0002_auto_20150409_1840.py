# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('attribute_aggregator', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='useraliasinsource',
            name='user',
            field=models.ForeignKey(related_name='user_alias_in_source', verbose_name='user', to=settings.AUTH_USER_MODEL),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='userattributeprofile',
            name='user',
            field=models.OneToOneField(related_name='user_attribute_profile', null=True, blank=True, to=settings.AUTH_USER_MODEL),
            preserve_default=True,
        ),
    ]
