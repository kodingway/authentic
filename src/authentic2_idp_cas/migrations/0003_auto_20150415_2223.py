# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0004_service'),
        ('authentic2_idp_cas', '0002_auto_20150410_1438'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServiceProxy2',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('from_service', models.IntegerField()),
                ('to_service', models.IntegerField()),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='service',
            name='service_ptr',
            field=models.OneToOneField(null=True, to='authentic2.Service'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='service',
            name='name',
            field=models.CharField(max_length=128, unique=True, null=True, verbose_name='name', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='service',
            name='slug',
            field=models.SlugField(null=True, max_length=128, blank=True, unique=True, verbose_name='slug'),
            preserve_default=True,
        ),
    ]
