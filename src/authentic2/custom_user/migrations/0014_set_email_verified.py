# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations


def noop(apps, schema_editor):
    pass


def set_email_verified(apps, schema_editor):
    User = apps.get_model('custom_user', 'User')
    User.objects.update(email_verified=True)


class Migration(migrations.Migration):

    dependencies = [
        ('custom_user', '0013_user_email_verified'),
    ]

    operations = [
        migrations.RunPython(set_email_verified, reverse_code=noop),
    ]
