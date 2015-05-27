# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations
from authentic2.migrations import CreatePartialIndexes

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0005_service_ou'),
    ]

    operations = [
        CreatePartialIndexes('Service', 'authentic2_service',
                             'authentic2_service_uniq_idx', ('ou_id',),
                             ('slug',)),
    ]
