# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

from authentic2.migrations import CreatePartialIndexes


class Migration(migrations.Migration):

    dependencies = [
        ('authentic2', '0012_auto_20160211_2255'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='attributevalue',
            unique_together=set([('content_type', 'object_id', 'attribute', 'multiple', 'content')]),
        ),
        CreatePartialIndexes('AttributeValue', 'authentic2_attributevalue',
                             'authentic2_attribute_value_partial_unique_idx',
                             (), ('content_type_id', 'object_id', 'attribute_id'),
                             where=("multiple = '0'",))
    ]
