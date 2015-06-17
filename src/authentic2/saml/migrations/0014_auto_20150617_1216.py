# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0013_auto_20150617_1004'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='libertysessiondump',
            unique_together=set([('django_session_key', 'kind')]),
        ),
    ]
