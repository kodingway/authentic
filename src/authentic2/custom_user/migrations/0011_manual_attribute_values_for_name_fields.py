# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations


def create_attribute_value_for_names(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '__first__'),
        ('custom_user', '0010_auto_20160307_1418'),
        ('authentic2', '0015_auto_20160621_1711'),
    ]

    operations = [
        migrations.RunPython(create_attribute_value_for_names, lambda *x: None),
    ]
