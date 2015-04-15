# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0006_copy_proxy_m2m'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='service',
            name='proxy',
        ),
        migrations.RenameField('Service', 'id', 'old_id'),
        migrations.RemoveField(
            model_name='service',
            name='name',
        ),
        migrations.RemoveField(
            model_name='service',
            name='slug',
        ),
        migrations.AlterField(
                model_name='Attribute',
                name='service',
                field=models.IntegerField(default=0),
                preserve_default=False
        ),
        migrations.AlterField(
                model_name='Ticket',
                name='service',
                field=models.IntegerField(default=0),
                preserve_default=False
        ),
        migrations.AlterField(
            model_name='service',
            name='old_id',
            field=models.IntegerField(null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='service',
            name='service_ptr',
            field=models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='authentic2.Service'),
            preserve_default=True,
        ),
    ]
