# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import authentic2.saml.fields


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Association',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('server_url', models.CharField(max_length=768)),
                ('handle', models.CharField(max_length=255)),
                ('secret', authentic2.saml.fields.PickledObjectField(editable=False)),
                ('issued', models.DateTimeField(verbose_name=b'Issue time for this association, as seconds since EPOCH', editable=False)),
                ('lifetime', models.IntegerField(verbose_name=b'Lifetime of this association as seconds since the issued time')),
                ('expire', models.DateTimeField(verbose_name=b'After this time, the association will be expired')),
                ('assoc_type', models.CharField(max_length=64)),
            ],
            options={
                'db_table': 'idp_openid_association',
                'verbose_name': 'association',
                'verbose_name_plural': 'associations',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Nonce',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('salt', models.CharField(max_length=40)),
                ('server_url', models.CharField(max_length=768)),
                ('timestamp', models.IntegerField()),
            ],
            options={
                'db_table': 'idp_openid_nonce',
                'verbose_name': 'nonce',
                'verbose_name_plural': 'nonces',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='TrustedRoot',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('user', models.CharField(max_length=255)),
                ('trust_root', models.CharField(max_length=200)),
                ('choices', authentic2.saml.fields.PickledObjectField()),
            ],
            options={
                'db_table': 'idp_openid_trustedroot',
                'verbose_name': 'trusted root',
                'verbose_name_plural': 'trusted roots',
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='nonce',
            unique_together=set([('server_url', 'salt')]),
        ),
        migrations.AlterUniqueTogether(
            name='association',
            unique_together=set([('server_url', 'handle')]),
        ),
    ]
