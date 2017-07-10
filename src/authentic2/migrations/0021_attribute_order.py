# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0020_delete_federatedid'),
    ]

    operations = [
        migrations.AddField(
            model_name='attribute',
            name='order',
            field=models.PositiveIntegerField(default=0, verbose_name='order'),
        ),
        migrations.AlterModelOptions(
            name='attribute',
            options={'ordering': ('order', 'id'), 'verbose_name': 'attribute definition', 'verbose_name_plural': 'attribute definitions'},
        ),
    ]
