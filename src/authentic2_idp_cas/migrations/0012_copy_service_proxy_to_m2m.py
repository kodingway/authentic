# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def copy_proxy_m2m_to_service_proxy(apps, schema_editor):
    ServiceProxy2 = apps.get_model('authentic2_idp_cas', 'ServiceProxy2')
    Service = apps.get_model('authentic2_idp_cas', 'Service')
    for service in Service.objects.all():
        for proxy in service.proxy.all():
            ServiceProxy2.objects.create(from_service=service.service_ptr_id, to_service=proxy.service_ptr_id)

def copy_service_proxy_to_m2m(apps, schema_editor):
    ServiceProxy2 = apps.get_model('authentic2_idp_cas', 'ServiceProxy2')
    Service = apps.get_model('authentic2_idp_cas', 'Service')
    for service in Service.objects.all():
        service.proxy.clear()
    for service_proxy in ServiceProxy2.objects.all():
        from_service = Service.objects.get(pk=service_proxy.from_service)
        to_service = Service.objects.get(pk=service_proxy.to_service)
        from_service.proxy.add(to_service)

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0011_remove_old_id_restore_proxy'),
    ]

    operations = [
        migrations.RunPython(copy_service_proxy_to_m2m,
            copy_proxy_m2m_to_service_proxy),
    ]
