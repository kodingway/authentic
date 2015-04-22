# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def alter_foreign_keys(apps, schema_editor):
    ContentType = apps.get_model('contenttypes', 'ContentType')
    LibertyProvider = apps.get_model('saml', 'LibertyProvider')
    LibertyServiceProvider = apps.get_model('saml', 'LibertyServiceProvider')
    LibertyIdentityProvider = apps.get_model('saml', 'LibertyIdentityProvider')
    LibertyFederation = apps.get_model('saml', 'LibertyFederation')
    SAMLAttribute = apps.get_model('saml', 'SAMLAttribute')
    for sp in LibertyServiceProvider.objects.all():
        lp = LibertyProvider.objects.get(old_id=sp.liberty_provider)
        LibertyServiceProvider.objects \
            .filter(liberty_provider=sp.liberty_provider) \
            .update(new_liberty_provider=lp.service_ptr_id)
    for idp in LibertyIdentityProvider.objects.all():
        lp = LibertyProvider.objects.get(old_id=idp.liberty_provider)
        LibertyIdentityProvider.objects \
            .filter(liberty_provider=idp.liberty_provider) \
            .update(new_liberty_provider=lp.service_ptr_id)
    try:
        lp_ct = ContentType.objects.get(app_label='saml', model='libertyprovider')
    except ContentType.DoesNotExist:
        # No contenttype so no attributes
        pass
    else:
        for a in SAMLAttribute.objects.filter(content_type=lp_ct):
            lp = LibertyProvider.objects.get(old_id=a.object_id)
            a.object_id = lp.service_ptr_id
            a.save()
    for fed in LibertyFederation.objects.all():
        if fed.idp:
	    lp = LibertyProvider.objects.get(old_id=fed.idp)
            fed.idp = lp.service_ptr_id
        if fed.sp:
	    lp = LibertyProvider.objects.get(old_id=fed.sp)
            fed.sp = lp.service_ptr_id
        fed.save()

def noop(apps, schema_editor):
    pass

def copy_service_ptr_id_to_old_id(apps, schema_editor):
    LibertyProvider = apps.get_model('saml', 'LibertyProvider')
    for lp in LibertyProvider.objects.all():
        lp.old_id = lp.service_ptr_id
        lp.save()

def restore_pk(apps, schema_editor):
    LibertyServiceProvider = apps.get_model('saml', 'LibertyServiceProvider')
    LibertyIdentityProvider = apps.get_model('saml', 'LibertyIdentityProvider')
    LibertyServiceProvider.objects.update(liberty_provider=models.F('new_liberty_provider_id'))
    LibertyIdentityProvider.objects.update(liberty_provider=models.F('new_liberty_provider_id'))

class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0007_copy_service_ptr_id_to_old_id'),
        ('contenttypes', '__first__'),
    ]

    operations = [
        migrations.AddField(
            model_name='libertyidentityprovider',
            name='new_liberty_provider',
            field=models.IntegerField(null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='libertyserviceprovider',
            name='new_liberty_provider',
            field=models.IntegerField(null=True),
            preserve_default=True,
        ),
        migrations.RunPython(alter_foreign_keys, noop),
        migrations.RunPython(noop, copy_service_ptr_id_to_old_id),
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
