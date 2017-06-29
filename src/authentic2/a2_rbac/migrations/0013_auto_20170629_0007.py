# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0011_auto_20160209_1511'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='roleparenting',
            unique_together=set([('parent', 'child', 'direct')]),
        ),
        migrations.AlterIndexTogether(
            name='roleparenting',
            index_together=set([('child', 'parent', 'direct')]),
        ),
    ]
