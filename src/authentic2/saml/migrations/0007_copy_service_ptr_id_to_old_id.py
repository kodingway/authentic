# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0006_restore_foreign_keys'),
    ]

    operations = [
        migrations.AlterField(
            model_name='libertyprovider',
            name='service_ptr',
            field=models.OneToOneField(to='authentic2.Service'),
            preserve_default=True,
        ),
        migrations.RenameField('LibertyProvider', 'id', 'old_id'),
        migrations.RemoveField(
            model_name='libertyprovider',
            name='name',
        ),
        migrations.RemoveField(
            model_name='libertyprovider',
            name='slug',
        ),
        migrations.AlterField(
                model_name='LibertyFederation',
                name='sp',
                field=models.IntegerField(null=True),
                preserve_default=False
        ),
        migrations.AlterField(
                model_name='LibertyFederation',
                name='idp',
                field=models.IntegerField(null=True),
                preserve_default=False
        ),
        migrations.AlterField(
                model_name='LibertyServiceProvider',
                name='liberty_provider',
                field=models.IntegerField(default=0, primary_key=True),
                preserve_default=False
        ),
        migrations.AlterField(
                model_name='LibertyIdentityProvider',
                name='liberty_provider',
                field=models.IntegerField(default=0, primary_key=True),
                preserve_default=False
        ),
        migrations.AlterField(
            model_name='libertyprovider',
            name='old_id',
            field=models.IntegerField(null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='libertyprovider',
            name='service_ptr',
            field=models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='authentic2.Service'),
            preserve_default=True,
        ),
        migrations.AlterModelOptions(
            name='libertyprovider',
            options={'ordering': ('service_ptr__name',), 'verbose_name': 'SAML provider', 'verbose_name_plural': 'SAML providers'},
        ),
    ]

