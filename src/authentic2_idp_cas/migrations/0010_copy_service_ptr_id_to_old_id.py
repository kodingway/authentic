# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def noop(apps, schema_editor):
    pass

def copy_service_ptr_id_to_old_id(apps, schema_editor):
    CasService = apps.get_model('authentic2_idp_cas', 'Service')
    for cas_service in CasService.objects.all():
        cas_service.old_id = cas_service.service_ptr_id
        cas_service.save()

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0009_alter_related_models'),
    ]

    operations = [
        migrations.RunPython(noop, copy_service_ptr_id_to_old_id),
    ]
