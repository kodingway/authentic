# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from authentic2.migrations import CreatePartialIndexes

class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0002_role_external_id'),
    ]

    operations = [
        CreatePartialIndexes('Role', 'a2_rbac_role', 'a2_rbac_role_unique_idx',
                             ('ou_id', 'service_id'), ('slug',),
                             null_columns=('admin_scope_ct_id',)),
    ]
