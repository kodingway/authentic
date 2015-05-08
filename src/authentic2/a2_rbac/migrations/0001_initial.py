# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import authentic2.utils
import authentic2.a2_rbac.fields
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0004_service'),
        ('django_rbac', '__first__'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('contenttypes', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='OrganizationalUnit',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', models.CharField(default=authentic2.utils.get_hex_uuid, unique=True, max_length=32, verbose_name='uuid')),
                ('name', models.CharField(max_length=256, verbose_name='name')),
                ('slug', models.SlugField(max_length=256, verbose_name='slug')),
                ('description', models.TextField(verbose_name='description', blank=True)),
                ('default', authentic2.a2_rbac.fields.UniqueBooleanField(verbose_name='Default organizational unit')),
            ],
            options={
                'verbose_name': 'organizational unit',
                'verbose_name_plural': 'organizational units',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Permission',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('target_id', models.PositiveIntegerField()),
                ('operation', models.ForeignKey(verbose_name='operation', to='django_rbac.Operation')),
                ('ou', models.ForeignKey(related_name='scoped_permission', verbose_name='organizational unit', to=settings.RBAC_OU_MODEL, null=True)),
                ('target_ct', models.ForeignKey(related_name='+', to='contenttypes.ContentType')),
            ],
            options={
                'verbose_name': 'permission',
                'verbose_name_plural': 'permissions',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', models.CharField(default=authentic2.utils.get_hex_uuid, unique=True, max_length=32, verbose_name='uuid')),
                ('name', models.CharField(max_length=256, verbose_name='name')),
                ('slug', models.SlugField(max_length=256, verbose_name='slug')),
                ('description', models.TextField(verbose_name='description', blank=True)),
                ('admin_scope_id', models.PositiveIntegerField(null=True, verbose_name='administrative scope id', blank=True)),
                ('admin_scope_ct', models.ForeignKey(verbose_name='administrative scope content type', blank=True, to='contenttypes.ContentType', null=True)),
                ('members', models.ManyToManyField(related_name='roles', to=settings.AUTH_USER_MODEL, blank=True)),
                ('ou', models.ForeignKey(verbose_name='organizational unit', blank=True, to=settings.RBAC_OU_MODEL, null=True)),
                ('permissions', models.ManyToManyField(related_name='role', to=settings.RBAC_PERMISSION_MODEL, blank=True)),
                ('service', models.ForeignKey(verbose_name='service', blank=True, to='authentic2.Service', null=True)),
            ],
            options={
                'ordering': ('ou', 'service', 'name'),
                'verbose_name': 'role',
                'verbose_name_plural': 'roles',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='RoleAttribute',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=64, verbose_name='name')),
                ('kind', models.CharField(max_length=32, verbose_name='kind', choices=[(b'string', 'string')])),
                ('value', models.TextField(verbose_name='value')),
                ('role', models.ForeignKey(related_name='attributes', verbose_name='role', to=settings.RBAC_ROLE_MODEL)),
            ],
            options={
                'verbose_name': 'role attribute',
                'verbose_name_plural': 'role attributes',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='RoleParenting',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('direct', models.BooleanField(default=True)),
                ('child', models.ForeignKey(related_name='parent_relation', to=settings.RBAC_ROLE_MODEL)),
                ('parent', models.ForeignKey(related_name='child_relation', to=settings.RBAC_ROLE_MODEL)),
            ],
            options={
                'verbose_name': 'role parenting relation',
                'verbose_name_plural': 'role parenting relations',
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='organizationalunit',
            unique_together=set([('name',), ('slug',)]),
        ),
        migrations.AlterUniqueTogether(
            name='roleattribute',
            unique_together=set([('role', 'name', 'kind', 'value')]),
        ),
        migrations.AlterUniqueTogether(
            name='role',
            unique_together=set([('slug', 'service'), ('slug', 'admin_scope_ct', 'admin_scope_id', 'ou')]),
        ),
    ]
