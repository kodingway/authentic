# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.utils.timezone
import authentic2.utils
import authentic2.validators

def noop(apps, schema_editor):
    pass

def copy_old_users_to_custom_user_model(apps, schema_editor):
    OldUser = apps.get_model('auth', 'User')
    NewUser = apps.get_model('custom_user', 'User')
    fields = ['id', 'username', 'email', 'first_name', 'last_name',
            'is_staff', 'is_active', 'date_joined', 'is_superuser',
            'last_login', 'password']
    old_users = OldUser.objects.select_related('groups', 'user_permissions')
    new_users = []
    for old_user in old_users:
        new_user = NewUser()
        for field in fields:
            setattr(new_user, field, getattr(old_user, field))
        new_users.append(new_user)
    # mass create of new users
    NewUser.objects.bulk_create(new_users)
    new_groups = []
    new_permissions = []
    GroupThrough = NewUser.groups.through
    PermissionThrough = NewUser.user_permissions.through
    for old_user, new_user in zip(old_users, new_users):
        new_user.groups.add(*old_user.groups.all())
        new_user.user_permissions.add(*old_user.user_permissions.all())
        for group in old_user.groups.all():
            new_groups.append(GroupThrough(user_id=new_user.id, group_id=group.id))
        for permission in old_user.user_permissions.all():
            new_permissions.append(PermissionThrough(user_id=new_user.id, group_id=group.id))
    # mass create group and permission relations
    GroupThrough.objects.bulk_create(new_groups)
    PermissionThrough.objects.bulk_create(new_permissions)
    # Reset sequences
    if schema_editor.connection.vendor == 'postgresql':
        schema_editor.execute('SELECT setval(pg_get_serial_sequence(\'"custom_user_user_groups"\',\'id\'), coalesce(max("id"), 1), max("id") IS NOT null) FROM "custom_user_user_groups";')
        schema_editor.execute('SELECT setval(pg_get_serial_sequence(\'"custom_user_user_user_permissions"\',\'id\'), coalesce(max("id"), 1), max("id") IS NOT null) FROM "custom_user_user_user_permissions";')
        schema_editor.execute('SELECT setval(pg_get_serial_sequence(\'"custom_user_user"\',\'id\'), coalesce(max("id"), 1), max("id") IS NOT null) FROM "custom_user_user";')
    elif schema_editor.connection.vendor == 'sqlite':
        schema_editor.execute('UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM custom_user_user) WHERE name = "custom_user_user";')
        schema_editor.execute('UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM custom_user_user_groups) WHERE name = "custom_user_user_groups";')
        schema_editor.execute('UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM custom_user_user_user_permissions) WHERE name = "custom_user_user_permissions";')
    else:
        raise NotImplementedError()



class Migration(migrations.Migration):

    dependencies = [
            ('auth', '__first__'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(default=django.utils.timezone.now, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('uuid', models.CharField(default=authentic2.utils.get_hex_uuid, verbose_name='uuid', unique=True, max_length=32, editable=False)),
                ('username', models.CharField(max_length=256, null=True, verbose_name='username', blank=True)),
                ('first_name', models.CharField(max_length=64, verbose_name='first name', blank=True)),
                ('last_name', models.CharField(max_length=64, verbose_name='last name', blank=True)),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address', validators=[authentic2.validators.EmailValidator])),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('groups', models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Group', blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of his/her group.', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Permission', blank=True, help_text='Specific permissions for this user.', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
            },
            bases=(models.Model,),
        ),
        migrations.RunPython(copy_old_users_to_custom_user_model, reverse_code=noop),
    ]
