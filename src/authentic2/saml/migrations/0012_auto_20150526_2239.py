# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('saml', '0011_auto'),
    ]

    operations = [
        migrations.AlterField(
            model_name='idpoptionssppolicy',
            name='http_method_for_defederation_request',
            field=models.IntegerField(default=5, verbose_name='HTTP method for the defederation requests', choices=[(4, 'Redirect binding'), (5, 'SOAP binding')]),
        ),
        migrations.AlterField(
            model_name='idpoptionssppolicy',
            name='http_method_for_slo_request',
            field=models.IntegerField(default=4, verbose_name='HTTP binding for the SLO requests', choices=[(4, 'Redirect binding'), (5, 'SOAP binding')]),
        ),
        migrations.AlterField(
            model_name='libertyprovider',
            name='protocol_conformance',
            field=models.IntegerField(choices=[(3, b'SAML 2.0')]),
        ),
    ]
