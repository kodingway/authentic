# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0016_auto_20150915_2041'),
    ]

    operations = [
        migrations.AlterField(
            model_name='libertyprovider',
            name='entity_id',
            field=models.URLField(unique=True, max_length=256),
        ),
    ]
