# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
            ('auth', '0002_auto_20150323_1720'),
    ]

    operations = [
        migrations.CreateModel(
            name='ClientCertificate',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('serial', models.CharField(max_length=255, blank=True)),
                ('subject_dn', models.CharField(max_length=255)),
                ('issuer_dn', models.CharField(max_length=255)),
                ('cert', models.TextField()),
                ('user', models.ForeignKey(to='auth.User')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
    ]
