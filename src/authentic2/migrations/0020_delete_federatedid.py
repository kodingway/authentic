# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0019_auto_20170309_1529'),
    ]

    operations = [
        migrations.DeleteModel(
            name='FederatedId',
        ),
    ]
