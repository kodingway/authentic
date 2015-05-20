# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def create_max_aggregate_function(apps, schema_editor):
    if not schema_editor.connection.vendor == 'postgresql':
        return
    schema_editor.execute('''create or replace function bor (boolean, boolean) returns boolean as $body$ select $1 or $2; $body$ language sql''')
    schema_editor.execute('''create aggregate max(boolean) (sfunc=bor, stype=boolean, initcond=false)''')


def drop_max_aggregate_function(apps, schema_editor):
    if not schema_editor.connection.vendor == 'postgresql':
        return
    schema_editor.execute('''drop aggregate max(boolean)''')
    schema_editor.execute('''drop function bor (boolean, boolean)''')


class Migration(migrations.Migration):

    dependencies = [
        ('django_rbac', '0002_organizationalunit_permission_role_roleparenting'),
    ]

    operations = [
        migrations.RunPython(create_max_aggregate_function,
                             reverse_code=drop_max_aggregate_function),
    ]
