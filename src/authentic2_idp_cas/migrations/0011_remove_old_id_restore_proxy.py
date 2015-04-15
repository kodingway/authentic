# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0010_copy_service_ptr_id_to_old_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='service',
            name='old_id',
        ),
        migrations.AddField(
            model_name='service',
            name='proxy',
            field=models.ManyToManyField(help_text='services who can request proxy tickets for this service', related_name='proxy_rel_+', verbose_name='proxy', to='authentic2_idp_cas.Service'),
            preserve_default=True,
        ),
    ]
