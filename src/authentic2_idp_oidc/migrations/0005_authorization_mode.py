# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


def set_client_ct(apps, schema_editor):
    OIDCClient = apps.get_model('authentic2_idp_oidc', 'oidcclient')
    OIDCAuthorization = apps.get_model('authentic2_idp_oidc', 'oidcauthorization')
    ContentType = apps.get_model('contenttypes', 'contenttype')

    ct = ContentType.objects.get_for_model(OIDCClient)
    OIDCAuthorization.objects.update(client_ct=ct)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_oidc', '0004_auto_20170324_1426'),
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='oidcclient',
            name='authorization_mode',
            field=models.PositiveIntegerField(default=1, verbose_name='authorization mode', choices=[(1, 'authorization by service'), (1, 'authorization by ou')]),
        ),
        migrations.AlterField(
            model_name='oidcauthorization',
            name='client',
            field=models.PositiveIntegerField(verbose_name='client'),
        ),
        migrations.RenameField(
            'oidcauthorization',
            'client',
            'client_id',
        ),
        migrations.AddField(
            model_name='oidcauthorization',
            name='client_ct',
            field=models.ForeignKey(verbose_name='client ct', to='contenttypes.ContentType', null=True),
        ),
        migrations.RunPython(set_client_ct, noop),
        migrations.AlterField(
            model_name='oidcauthorization',
            name='client_id',
            field=models.PositiveIntegerField(verbose_name='client id'),
        ),
        migrations.AlterField(
            model_name='oidcauthorization',
            name='client_ct',
            field=models.ForeignKey(verbose_name='client ct', to='contenttypes.ContentType'),
        ),
    ]
