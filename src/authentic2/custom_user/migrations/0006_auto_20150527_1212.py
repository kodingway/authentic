# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def noop(apps, schema_editor):
    pass

def set_last_login(apps, schema_editor):
    User = apps.get_model('custom_user', 'User')
    User.objects.filter(last_login__isnull=True) \
        .update(last_login=models.F('date_joined'))

class Migration(migrations.Migration):

    dependencies = [
        ('custom_user', '0005_auto_20150522_1527'),
    ]

    operations = [
        migrations.RunPython(set_last_login, noop),
    ]
