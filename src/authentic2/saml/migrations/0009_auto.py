# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0008_alter_foreign_keys'),
    ]

    operations = [
        migrations.AlterField(
            model_name='libertyidentityprovider',
            name='liberty_provider',
            field=models.IntegerField(null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='libertyserviceprovider',
            name='liberty_provider',
            field=models.IntegerField(null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='libertyidentityprovider',
            name='new_liberty_provider',
            field=models.OneToOneField(related_name='identity_provider', primary_key=True, serialize=False, to='saml.LibertyProvider'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='libertyserviceprovider',
            name='new_liberty_provider',
            field=models.OneToOneField(related_name='service_provider', primary_key=True, serialize=False, to='saml.LibertyProvider'),
            preserve_default=True,
        ),
    ]

