# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.RBAC_ROLE_MODEL),
        ('authentic2', '0017_modify_attribute_serialization'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthorizedRole',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('role', models.ForeignKey(to=settings.RBAC_ROLE_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='service',
            name='unauthorized_url',
            field=models.URLField(max_length=256, null=True, verbose_name='callback url when unauthorized', blank=True),
        ),
        migrations.AddField(
            model_name='authorizedrole',
            name='service',
            field=models.ForeignKey(to='authentic2.Service'),
        ),
        migrations.AddField(
            model_name='service',
            name='authorized_roles',
            field=models.ManyToManyField(related_name='authorized_roles', verbose_name='authorized services', to=settings.RBAC_ROLE_MODEL, through='authentic2.AuthorizedRole', blank=True),
        ),
    ]
