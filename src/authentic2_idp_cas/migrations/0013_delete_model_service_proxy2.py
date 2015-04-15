# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

    dependencies = [
        ('authentic2_idp_cas', '0012_copy_service_proxy_to_m2m'),
    ]

    operations = [
        migrations.DeleteModel('ServiceProxy2'),
    ]

