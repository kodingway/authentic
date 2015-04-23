# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def noop(apps, schema_editor):
    pass

def restore_pk(apps, schema_editor):
    LibertyServiceProvider = apps.get_model('saml', 'LibertyServiceProvider')
    LibertyIdentityProvider = apps.get_model('saml', 'LibertyIdentityProvider')
    LibertyServiceProvider.objects.update(liberty_provider=models.F('new_liberty_provider_id'))
    LibertyIdentityProvider.objects.update(liberty_provider=models.F('new_liberty_provider_id'))

class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0009_auto'),
    ]

    operations = [
        migrations.RunPython(noop, restore_pk),
    ]

