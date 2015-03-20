# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='libertyserviceprovider',
            name='enabled',
            field=models.BooleanField(default=False, db_index=True, verbose_name='Enabled'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='libertyserviceprovider',
            name='users_can_manage_federations',
            field=models.BooleanField(default=True, db_index=True, verbose_name='users can manage federation'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='spoptionsidppolicy',
            name='accept_slo',
            field=models.BooleanField(default=True, db_index=True, verbose_name='Accept to receive Single Logout requests'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='spoptionsidppolicy',
            name='enabled',
            field=models.BooleanField(default=False, db_index=True, verbose_name='Enabled'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='spoptionsidppolicy',
            name='idp_initiated_sso',
            field=models.BooleanField(default=False, db_index=True, verbose_name='Allow IdP initiated SSO'),
            preserve_default=True,
        ),
    ]
