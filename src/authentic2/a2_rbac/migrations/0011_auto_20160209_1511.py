# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0010_auto_20160209_1417'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='role',
            unique_together=set([('admin_scope_ct', 'admin_scope_id')]),
        ),
    ]
