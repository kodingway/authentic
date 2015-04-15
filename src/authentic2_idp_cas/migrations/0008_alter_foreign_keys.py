# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def alter_foreign_keys(apps, schema_editor):
    Service = apps.get_model('authentic2_idp_cas', 'Service')
    Attribute = apps.get_model('authentic2_idp_cas', 'Attribute')
    Ticket = apps.get_model('authentic2_idp_cas', 'Ticket')
    for attribute in Attribute.objects.all():
        service = Service.objects.get(old_id=attribute.service)
        attribute.service = service.service_ptr_id
        attribute.save()
    for ticket in Ticket.objects.all():
        service = Service.objects.get(old_id=ticket.service)
        ticket.service = service.service_ptr_id
        ticket.save()

def noop(apps, schema_editor):
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0007_alter_service'),
    ]

    operations = [
        migrations.RunPython(alter_foreign_keys, noop),
    ]
