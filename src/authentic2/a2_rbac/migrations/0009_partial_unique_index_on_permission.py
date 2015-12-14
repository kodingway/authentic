# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from authentic2.migrations import CreatePartialIndexes

class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0008_auto_20150810_1953'),
    ]

    operations = [
        CreatePartialIndexes('Permission', 'a2_rbac_permission', 'a2_rbac_permission_null_ou_unique_idx',
                             ('ou_id',), ('operation_id', 'target_ct_id', 'target_id'))
    ]
