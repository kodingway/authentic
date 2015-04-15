# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0008_alter_foreign_keys'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attribute',
            name='service',
            field=models.ForeignKey(verbose_name='service', to='authentic2_idp_cas.Service'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='ticket',
            name='service',
            field=models.ForeignKey(verbose_name='service', to='authentic2_idp_cas.Service'),
            preserve_default=True,
        ),
    ]
