# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0004_create_services'),
    ]

    operations = [
        migrations.AlterField(
            model_name='service',
            name='service_ptr',
            field=models.OneToOneField(to='authentic2.Service'),
            preserve_default=True,
        ),
    ]
