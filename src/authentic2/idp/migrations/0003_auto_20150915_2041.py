# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0016_auto_20150915_2041'),
        ('idp', '0002_auto_20150526_2239'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='attributepolicy',
            name='attribute_filter_for_sso_from_push_sources',
        ),
        migrations.RemoveField(
            model_name='attributepolicy',
            name='attribute_list_for_sso_from_pull_sources',
        ),
        migrations.RemoveField(
            model_name='attributepolicy',
            name='source_filter_for_sso_from_push_sources',
        ),
        migrations.DeleteModel(
            name='AttributePolicy',
        ),
    ]
