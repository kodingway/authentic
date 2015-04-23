# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def noop(apps, schema_editor):
    pass

def restore_pk(apps, schema_editor):
    LibertyServiceProvider = apps.get_model('saml', 'LibertyServiceProvider')
    LibertyIdentityProvider = apps.get_model('saml', 'LibertyIdentityProvider')
    LibertyServiceProvider.objects.update(liberty_provider=models.F('new_liberty_provider_id'))
    LibertyIdentityProvider.objects.update(liberty_provider=models.F('new_liberty_provider_id'))

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
        migrations.RunPython(noop, restore_pk),
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

