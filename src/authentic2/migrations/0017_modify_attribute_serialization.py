# -*- coding: utf-8 -*-
import json

from django.db import migrations


def clean_null(apps, schema_editor):
    AttributeValue = apps.get_model('authentic2', 'AttributeValue')
    AttributeValue.objects.filter(attribute__required=True, content='null').update(content='""')
    AttributeValue.objects.filter(attribute__required=False, content='null').delete()
    AttributeValue.objects.filter(attribute__required=False, content='""').delete()


def noop(apps, schema_editor):
    pass


def modify_string_serialization(apps, schema_editor):
    AttributeValue = apps.get_model('authentic2', 'AttributeValue')
    for atv in AttributeValue.objects.filter(attribute__kind__in=['string', 'title']):
        b = json.loads(atv.content)
        assert isinstance(b, unicode)
        atv.content = b
        atv.save()


def reverse_modify_string_serialization(apps, schema_editor):
    AttributeValue = apps.get_model('authentic2', 'AttributeValue')
    for atv in AttributeValue.objects.filter(attribute__kind__in=['string', 'title']):
        atv.content = json.dumps(atv.content)
        atv.save()


def modify_boolean_serialization(apps, schema_editor):
    AttributeValue = apps.get_model('authentic2', 'AttributeValue')
    for atv in AttributeValue.objects.filter(attribute__kind='boolean'):
        b = json.loads(atv.content)
        atv.content = str(int(bool(b)))
        atv.save()


def reverse_modify_boolean_serialization(apps, schema_editor):
    AttributeValue = apps.get_model('authentic2', 'AttributeValue')
    for atv in AttributeValue.objects.filter(attribute__kind='boolean'):
        b = bool(int(atv.content))
        atv.content = json.dumps(b)
        atv.save()


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0016_attribute_disabled'),
    ]

    operations = [
        migrations.RunPython(clean_null, noop),
        migrations.RunPython(modify_string_serialization, reverse_modify_string_serialization),
        migrations.RunPython(modify_boolean_serialization, reverse_modify_boolean_serialization),
    ]
