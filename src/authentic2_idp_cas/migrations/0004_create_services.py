# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def create_services(apps, schema_editor):
    Service = apps.get_model('authentic2', 'Service')
    CasService = apps.get_model('authentic2_idp_cas', 'Service')
    for cas_service in CasService.objects.all():
        service = Service.objects.create(name=cas_service.name,
                    slug=cas_service.slug)
        cas_service.service_ptr = service
        cas_service.save()

def move_back_name_and_slug(apps, schema_editor):
    CasService = apps.get_model('authentic2_idp_cas', 'Service')
    for cas_service in CasService.objects.all():
        cas_service.name = cas_service.service_ptr.name
        cas_service.slug = cas_service.service_ptr.slug
        cas_service.save()

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0003_auto_20150415_2223'),
    ]

    operations = [
        migrations.RunPython(create_services, move_back_name_and_slug),
    ]
