# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0015_auto_20150915_2032'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='authorizationattributemapping',
            name='map',
        ),
        migrations.DeleteModel(
            name='AuthorizationAttributeMapping',
        ),
        migrations.RemoveField(
            model_name='authorizationsppolicy',
            name='attribute_map',
        ),
        migrations.DeleteModel(
            name='AuthorizationAttributeMap',
        ),
        migrations.RemoveField(
            model_name='libertyidentityprovider',
            name='authorization_policy',
        ),
        migrations.DeleteModel(
            name='AuthorizationSPPolicy',
        ),
        migrations.RemoveField(
            model_name='libertyidentityprovider',
            name='idp_options_policy',
        ),
        migrations.DeleteModel(
            name='IdPOptionsSPPolicy',
        ),
        migrations.RemoveField(
            model_name='libertyidentityprovider',
            name='liberty_provider',
        ),
        migrations.DeleteModel(
            name='LibertyManageDump',
        ),
        migrations.RemoveField(
            model_name='libertysessionsp',
            name='federation',
        ),
        migrations.DeleteModel(
            name='LibertySessionSP',
        ),
        migrations.RemoveField(
            model_name='libertyfederation',
            name='idp',
        ),
        migrations.DeleteModel(
            name='LibertyIdentityProvider',
        ),
        migrations.RemoveField(
            model_name='libertyserviceprovider',
            name='attribute_policy',
        ),
        migrations.RemoveField(
            model_name='libertyserviceprovider',
            name='enable_following_attribute_policy',
        ),
    ]
