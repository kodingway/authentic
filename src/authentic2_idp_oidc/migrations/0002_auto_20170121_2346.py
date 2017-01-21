# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import authentic2_idp_oidc.models


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_oidc', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='oidcclient',
            name='post_logout_redirect_uris',
            field=models.TextField(default=b'', verbose_name='post logout redirect URIs', validators=[authentic2_idp_oidc.models.validate_https_url]),
        ),
    ]
