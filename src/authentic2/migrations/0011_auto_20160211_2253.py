# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


def fill_attribute_value_multiple(apps, schema_editor):
    AttributeValue = apps.get_model('authentic2', 'AttributeValue')
    for atv in AttributeValue.objects.select_related('attribute'):
        atv.multiple = atv.attribute.multiple
        atv.save()


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0010_attributevalue_multiple'),
    ]

    operations = [
        migrations.RunPython(fill_attribute_value_multiple, noop),
    ]
