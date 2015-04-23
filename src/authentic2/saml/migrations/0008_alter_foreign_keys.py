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
    ]
