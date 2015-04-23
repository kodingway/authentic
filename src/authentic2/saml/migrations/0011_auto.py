# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0010_auto'),
    ]

    operations = [
        migrations.RemoveField(
            'libertyidentityprovider',
            'liberty_provider'),
        migrations.RemoveField(
            'libertyserviceprovider',
            'liberty_provider'),
        migrations.RenameField(
            'libertyidentityprovider',
            'new_liberty_provider',
            'liberty_provider'),
        migrations.RenameField(
            'libertyserviceprovider',
            'new_liberty_provider',
            'liberty_provider'),
        migrations.AlterField(
            model_name='libertyfederation',
            name='idp',
            field=models.ForeignKey(blank=True, to='saml.LibertyIdentityProvider', null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='libertyfederation',
            name='sp',
            field=models.ForeignKey(blank=True, to='saml.LibertyServiceProvider', null=True),
            preserve_default=True,
        ),
        migrations.RemoveField(
            model_name='libertyprovider',
            name='old_id',
        ),
    ]

