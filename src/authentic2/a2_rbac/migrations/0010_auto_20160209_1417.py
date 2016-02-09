# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from collections import defaultdict

from django.db import migrations


def deduplicate_admin_roles(apps, schema_editor):
    '''Find duplicated admin roles, only keep the one with the lowest id and
       copy all members, parent and children of other duplicated roles to it,
       then delete duplicates with greater id.
    '''
    Role = apps.get_model('a2_rbac', 'Role')
    RoleParenting = apps.get_model('a2_rbac', 'RoleParenting')
    qs = Role.objects.filter(admin_scope_ct__isnull=False,
                             admin_scope_id__isnull=False).order_by('id')

    roles = defaultdict(lambda: [])
    for role in qs:
        roles[(role.admin_scope_ct, role.admin_scope_id)].append(role)
    for duplicates in roles.values():
        if len(duplicates) < 2:
            continue
        members = set()
        parents = set()
        children = set()
        for role in duplicates:
            members |= set(role.members.all())
            parents |= set(
                rp.parent for rp in RoleParenting.objects.filter(child=role, direct=True))
            children |= set(
                rp.child for rp in RoleParenting.objects.filter(parent=role, direct=True))
        duplicates[0].members = members
        for parent in parents:
            RoleParenting.objects.get_or_crate(
                parent=parent,
                child=duplicates[0],
                direct=True)
        for child in children:
            RoleParenting.objects.get_or_create(
                parent=duplicates[0],
                child=child,
                direct=True)
        for role in duplicates[1:]:
            role.delete()


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('a2_rbac', '0009_partial_unique_index_on_permission'),
    ]

    operations = [
        migrations.RunPython(deduplicate_admin_roles, noop),
    ]
