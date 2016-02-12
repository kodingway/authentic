# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def deduplicate_attribute_values(apps, schema_editor):
    AttributeValue = apps.get_model('authentic2', 'AttributeValue')
    seen = set()
    for atv in AttributeValue.objects.select_related('attribute').order_by('-id').all():
        if atv.attribute.multiple:
            k = (atv.content_type_id, atv.object_id, atv.attribute_id, atv.content)
        else:
            k = (atv.content_type_id, atv.object_id, atv.attribute_id)
        if k in seen:
            atv.delete()
        else:
            seen.add(k)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0008_auto_20160204_1415'),
    ]

    operations = [
        migrations.RunPython(deduplicate_attribute_values, noop),
    ]
