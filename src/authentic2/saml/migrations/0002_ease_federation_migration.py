# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models

from authentic2.saml.common import AUTHENTIC_SAME_ID_SENTINEL

def use_id_sentinel(apps, schema_editor):
    LibertyFederation = apps.get_model('saml', 'LibertyFederation')
    # idp federations
    LibertyFederation.objects.filter(idp__isnull=True,
            name_id_sp_name_qualifier=models.F('sp__liberty_provider__entity_id')) \
            .update(name_id_sp_name_qualifier=AUTHENTIC_SAME_ID_SENTINEL)
    # If there is NameIDQualifier it must be ours
    LibertyFederation.objects.filter(idp__isnull=True, name_id_qualifier__isnull=False) \
            .update(name_id_qualifier=AUTHENTIC_SAME_ID_SENTINEL)

class Migration(migrations.Migration):
    dependencies = [
        ('saml', '0001_initial'),
    ]
    operations = [
            migrations.RunPython(use_id_sentinel),
    ]
