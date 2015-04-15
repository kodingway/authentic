# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0002_auto_20150323_1720'),
        ('contenttypes', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Attribute',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('label', models.CharField(unique=True, max_length=63, verbose_name='label')),
                ('description', models.TextField(verbose_name='description', blank=True)),
                ('name', models.SlugField(unique=True, max_length=256, verbose_name='name')),
                ('required', models.BooleanField(default=False, verbose_name='required')),
                ('asked_on_registration', models.BooleanField(default=False, verbose_name='asked on registration')),
                ('user_editable', models.BooleanField(default=False, verbose_name='user editable')),
                ('user_visible', models.BooleanField(default=False, verbose_name='user visible')),
                ('multiple', models.BooleanField(default=False, verbose_name='multiple')),
                ('kind', models.CharField(max_length=16, verbose_name='kind', choices=[(b'string', '<django.utils.functional.__proxy__ object at 0x303d350>')])),
            ],
            options={
                'verbose_name': 'attribute definition',
                'verbose_name_plural': 'attribute definitions',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='AttributeValue',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('object_id', models.PositiveIntegerField(verbose_name='object identifier')),
                ('content', models.TextField(verbose_name='content')),
                ('attribute', models.ForeignKey(verbose_name='attribute', to='authentic2.Attribute')),
                ('content_type', models.ForeignKey(verbose_name='content type', to='contenttypes.ContentType')),
            ],
            options={
                'verbose_name': 'attribute value',
                'verbose_name_plural': 'attribute values',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='AuthenticationEvent',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('when', models.DateTimeField(auto_now=True, verbose_name='when')),
                ('who', models.CharField(max_length=80, verbose_name='who')),
                ('how', models.CharField(max_length=32, verbose_name='how')),
                ('nonce', models.CharField(max_length=255, verbose_name='nonce')),
            ],
            options={
                'verbose_name': 'authentication log',
                'verbose_name_plural': 'authentication logs',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='DeletedUser',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('creation', models.DateTimeField(auto_now_add=True, verbose_name='creation date')),
                ('user', models.ForeignKey(verbose_name='user', to='auth.User')),
            ],
            options={
                'verbose_name': 'user to delete',
                'verbose_name_plural': 'users to delete',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='FederatedId',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('provider', models.CharField(max_length=255, verbose_name='provider')),
                ('about', models.CharField(max_length=255, verbose_name='about')),
                ('service', models.CharField(max_length=255, verbose_name='service')),
                ('id_format', models.CharField(max_length=128, verbose_name='format identifier')),
                ('id_value', models.TextField(verbose_name='identifier')),
            ],
            options={
                'verbose_name': 'federation identifier',
                'verbose_name_plural': 'federation identifiers',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LogoutUrl',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('logout_url', models.URLField(help_text='you can use a {} to pass the URL of the success icon, ex.: http://example.com/logout?next={}', max_length=255, null=True, verbose_name='url', blank=True)),
                ('logout_use_iframe', models.BooleanField(default=False, verbose_name='use an iframe instead of an img tag for logout')),
                ('logout_use_iframe_timeout', models.PositiveIntegerField(default=300, help_text="if iframe logout is used, it's the time between the onload event for this iframe and the moment we consider its loading to be really finished", verbose_name='iframe logout timeout (ms)')),
                ('object_id', models.PositiveIntegerField(verbose_name='object identifier')),
                ('content_type', models.ForeignKey(verbose_name='content type', to='contenttypes.ContentType')),
            ],
            options={
                'verbose_name': 'logout URL',
                'verbose_name_plural': 'logout URL',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='PasswordReset',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('user', models.ForeignKey(verbose_name='user', to='auth.User')),
            ],
            options={
                'verbose_name': 'password reset',
                'verbose_name_plural': 'password reset',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserExternalId',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('source', models.URLField(max_length=256, verbose_name='source')),
                ('external_id', models.CharField(max_length=256, verbose_name='external id')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='creation date')),
                ('updated', models.DateTimeField(auto_now=True, verbose_name='last update date')),
                ('user', models.ForeignKey(verbose_name='user', to='auth.User')),
            ],
            options={
                'verbose_name': 'user external id',
                'verbose_name_plural': 'user external ids',
            },
            bases=(models.Model,),
        ),
    ]
