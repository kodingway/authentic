# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('idp', '0003_auto_20150915_2041'),
        ('attribute_aggregator', '0003_auto_20150526_2239'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='attributeitem',
            name='source',
        ),
        migrations.RemoveField(
            model_name='attributelist',
            name='attributes',
        ),
        migrations.DeleteModel(
            name='AttributeItem',
        ),
        migrations.DeleteModel(
            name='AttributeList',
        ),
        migrations.RemoveField(
            model_name='ldapsource',
            name='attributesource_ptr',
        ),
        migrations.AlterUniqueTogether(
            name='useraliasinsource',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='useraliasinsource',
            name='source',
        ),
        migrations.DeleteModel(
            name='LdapSource',
        ),
        migrations.DeleteModel(
            name='AttributeSource',
        ),
        migrations.RemoveField(
            model_name='useraliasinsource',
            name='user',
        ),
        migrations.DeleteModel(
            name='UserAliasInSource',
        ),
        migrations.RemoveField(
            model_name='userattributeprofile',
            name='user',
        ),
        migrations.DeleteModel(
            name='UserAttributeProfile',
        ),
    ]
