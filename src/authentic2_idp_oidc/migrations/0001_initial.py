# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings
import authentic2_idp_oidc.models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('authentic2', '0016_attribute_disabled'),
    ]

    operations = [
        migrations.CreateModel(
            name='OIDCAccessToken',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', models.CharField(default=authentic2_idp_oidc.models.generate_uuid, max_length=128, verbose_name='uuid')),
                ('scopes', models.TextField(verbose_name='scopes')),
                ('session_key', models.CharField(max_length=128, verbose_name='session key')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('expired', models.DateTimeField(verbose_name='expire')),
            ],
        ),
        migrations.CreateModel(
            name='OIDCAuthorization',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('scopes', models.TextField(verbose_name='scopes')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('expired', models.DateTimeField(verbose_name='expire')),
            ],
        ),
        migrations.CreateModel(
            name='OIDCClient',
            fields=[
                ('service_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='authentic2.Service')),
                ('client_id', models.CharField(default=authentic2_idp_oidc.models.generate_uuid, unique=True, max_length=255, verbose_name='client id')),
                ('client_secret', models.CharField(default=authentic2_idp_oidc.models.generate_uuid, max_length=255, verbose_name='client secret')),
                ('authorization_flow', models.PositiveIntegerField(default=1, verbose_name='authorization flow', choices=[(1, 'authorization code'), (2, 'implicit/native')])),
                ('redirect_uris', models.TextField(verbose_name='redirect URIs', validators=[authentic2_idp_oidc.models.validate_https_url])),
                ('sector_identifier_uri', models.URLField(verbose_name='sector identifier URI', blank=True)),
                ('identifier_policy', models.PositiveIntegerField(default=2, verbose_name='identifier policy', choices=[(1, 'uuid'), (2, 'pairwise'), (3, 'email')])),
                ('idtoken_algo', models.PositiveIntegerField(default=1, verbose_name='IDToken signature algorithm', choices=[(1, 'RSA'), (2, 'HMAC')])),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('modified', models.DateTimeField(auto_now=True, verbose_name='modified')),
            ],
            bases=('authentic2.service',),
        ),
        migrations.CreateModel(
            name='OIDCCode',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', models.CharField(default=authentic2_idp_oidc.models.generate_uuid, max_length=128, verbose_name='uuid')),
                ('scopes', models.TextField(verbose_name='scopes')),
                ('state', models.TextField(verbose_name='state')),
                ('nonce', models.TextField(verbose_name='nonce')),
                ('redirect_uri', models.URLField(verbose_name='redirect URI')),
                ('session_key', models.CharField(max_length=128, verbose_name='session key')),
                ('auth_time', models.DateTimeField(verbose_name='auth time')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('expired', models.DateTimeField(verbose_name='expire')),
                ('client', models.ForeignKey(verbose_name='client', to='authentic2_idp_oidc.OIDCClient')),
                ('user', models.ForeignKey(verbose_name='user', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='oidcauthorization',
            name='client',
            field=models.ForeignKey(verbose_name='client', to='authentic2_idp_oidc.OIDCClient'),
        ),
        migrations.AddField(
            model_name='oidcauthorization',
            name='user',
            field=models.ForeignKey(verbose_name='user', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='oidcaccesstoken',
            name='client',
            field=models.ForeignKey(verbose_name='client', to='authentic2_idp_oidc.OIDCClient'),
        ),
        migrations.AddField(
            model_name='oidcaccesstoken',
            name='user',
            field=models.ForeignKey(verbose_name='user', to=settings.AUTH_USER_MODEL),
        ),
    ]
