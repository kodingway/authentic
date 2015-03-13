# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import authentic2_idp_cas.models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Attribute',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('slug', models.SlugField(verbose_name='slug')),
                ('attribute_name', models.CharField(max_length=64, verbose_name='attribute name')),
                ('enabled', models.BooleanField(default=True, verbose_name='enabled')),
            ],
            options={
                'verbose_name': 'CAS attribute',
                'verbose_name_plural': 'CAS attributes',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Service',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('logout_url', models.URLField(help_text='you can use a {} to pass the URL of the success icon, ex.: http://example.com/logout?next={}', max_length=255, null=True, verbose_name='url', blank=True)),
                ('logout_use_iframe', models.BooleanField(default=False, verbose_name='use an iframe instead of an img tag for logout')),
                ('logout_use_iframe_timeout', models.PositiveIntegerField(default=300, help_text="if iframe logout is used, it's the time between the onload event for this iframe and the moment we consider its loading to be really finished", verbose_name='iframe logout timeout (ms)')),
                ('name', models.CharField(unique=True, max_length=128, verbose_name='name')),
                ('slug', models.SlugField(unique=True, max_length=128, verbose_name='slug')),
                ('urls', models.TextField(max_length=128, verbose_name='urls')),
                ('identifier_attribute', models.CharField(max_length=64, verbose_name='attribute name')),
                ('proxy', models.ManyToManyField(help_text='services who can request proxy tickets for this service', related_name='proxy_rel_+', verbose_name='proxy', to='authentic2_idp_cas.Service')),
            ],
            options={
                'verbose_name': 'service',
                'verbose_name_plural': 'services',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Ticket',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('ticket_id', models.CharField(default=authentic2_idp_cas.models.make_uuid, unique=True, max_length=64, verbose_name='ticket id')),
                ('renew', models.BooleanField(default=False, verbose_name='fresh authentication')),
                ('validity', models.BooleanField(default=False, verbose_name='valid')),
                ('service_url', models.CharField(default=b'', max_length=256, verbose_name='service URL', blank=True)),
                ('creation', models.DateTimeField(auto_now_add=True, verbose_name='creation')),
                ('expire', models.DateTimeField(null=True, verbose_name='expire', blank=True)),
                ('session_key', models.CharField(default=b'', max_length=64, verbose_name='django session key', db_index=True, blank=True)),
                ('proxies', models.TextField(default=b'', verbose_name='proxies', blank=True)),
                ('service', models.ForeignKey(verbose_name='service', to='authentic2_idp_cas.Service')),
                ('user', models.ForeignKey(blank=True, to=settings.AUTH_USER_MODEL, max_length=128, null=True, verbose_name='user')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='attribute',
            name='service',
            field=models.ForeignKey(verbose_name='service', to='authentic2_idp_cas.Service'),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='attribute',
            unique_together=set([('service', 'slug', 'attribute_name')]),
        ),
    ]
