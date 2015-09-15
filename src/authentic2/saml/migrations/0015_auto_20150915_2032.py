# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import authentic2.saml.fields


class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0014_auto_20150617_1216'),
    ]

    operations = [
        migrations.AlterField(
            model_name='idpoptionssppolicy',
            name='requested_name_id_format',
            field=models.CharField(default=b'none', max_length=200, verbose_name='Requested NameID format', choices=[(b'username', 'Username (use with Google Apps)'), (b'none', 'None'), (b'uuid', 'UUID'), (b'persistent', 'Persistent'), (b'transient', 'Transient'), (b'edupersontargetedid', 'Use eduPersonTargetedID attribute'), (b'email', 'Email')]),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='spoptionsidppolicy',
            name='accepted_name_id_format',
            field=authentic2.saml.fields.MultiSelectField(blank=True, max_length=1024, verbose_name='NameID formats accepted', choices=[(b'username', 'Username (use with Google Apps)'), (b'none', 'None'), (b'uuid', 'UUID'), (b'persistent', 'Persistent'), (b'transient', 'Transient'), (b'edupersontargetedid', 'Use eduPersonTargetedID attribute'), (b'email', 'Email')]),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='spoptionsidppolicy',
            name='default_name_id_format',
            field=models.CharField(default=b'none', max_length=256, choices=[(b'username', 'Username (use with Google Apps)'), (b'none', 'None'), (b'uuid', 'UUID'), (b'persistent', 'Persistent'), (b'transient', 'Transient'), (b'edupersontargetedid', 'Use eduPersonTargetedID attribute'), (b'email', 'Email')]),
            preserve_default=True,
        ),
    ]
