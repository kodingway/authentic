# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def noop(apps, schema_editor):
    pass

def remove_duplicate_session_dump(apps, schema_editor):
    LibertySessionDump = apps.get_model('saml', 'LibertySessionDump')
    qs = LibertySessionDump.objects \
        .values('django_session_key') \
        .annotate(cnt=models.Count('django_session_key')) \
        .filter(cnt__gt=1)
    session_keys = [d['django_session_key'] for d in qs]
    LibertySessionDump.objects.filter(django_session_key__in=session_keys).delete()

class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0012_auto_20150526_2239'),
    ]

    operations = [
        migrations.RunPython(remove_duplicate_session_dump, reverse_code=noop),
    ]
