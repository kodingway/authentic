# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def create_services(apps, schema_editor):
    Service = apps.get_model('authentic2', 'Service')
    LibertyProvider = apps.get_model('saml', 'LibertyProvider')
    for lp in LibertyProvider.objects.all():
        service = Service.objects.create(name=lp.name, slug=lp.slug)
        lp.service_ptr = service
        lp.save()

def move_back_name_and_slug(apps, schema_editor):
    LibertyProvider = apps.get_model('saml', 'LibertyProvider')
    for lp in LibertyProvider.objects.all():
        lp.name = lp.service_ptr.name
        lp.slug = lp.service_ptr.slug
        lp.save()

class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0005_make_liberty_provider_inherit_from_service'),
        ('contenttypes', '__first__'),
    ]

    operations = [
        migrations.RunPython(create_services, move_back_name_and_slug),
    ]
