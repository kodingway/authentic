# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0014_auto_20151204_1606'),
    ]

    operations = [
        migrations.AlterField(
            model_name='service',
            name='proxy',
            field=models.ManyToManyField(help_text='services who can request proxy tickets for this service', related_name='_service_proxy_+', verbose_name='proxy', to='authentic2_idp_cas.Service', blank=True),
        ),
    ]
