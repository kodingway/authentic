# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import authentic2.saml.models
import django.db.models.deletion
import authentic2.saml.fields


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '__first__'),
        ('idp', '__first__'),
        ('contenttypes', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthorizationAttributeMap',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=40)),
            ],
            options={
                'verbose_name': 'authorization attribute map',
                'verbose_name_plural': 'authorization attribute maps',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='AuthorizationAttributeMapping',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('source_attribute_name', models.CharField(max_length=40, blank=True)),
                ('attribute_value_format', models.CharField(max_length=40, blank=True)),
                ('attribute_name', models.CharField(max_length=40)),
                ('attribute_value', models.CharField(max_length=40)),
                ('map', models.ForeignKey(to='saml.AuthorizationAttributeMap')),
            ],
            options={
                'verbose_name': 'authorization attribute mapping',
                'verbose_name_plural': 'authorization attribute mappings',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='AuthorizationSPPolicy',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=80, verbose_name='name')),
                ('enabled', models.BooleanField(default=False, verbose_name='Enabled')),
                ('default_denial_message', models.CharField(default='You are not authorized to access the service.', max_length=80, verbose_name='Default message to display to the user when access is denied')),
                ('attribute_map', models.ForeignKey(related_name='authorization_attributes', blank=True, to='saml.AuthorizationAttributeMap', null=True)),
            ],
            options={
                'verbose_name': 'authorization identity providers policy',
                'verbose_name_plural': 'authorization identity providers policies',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='IdPOptionsSPPolicy',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=200, verbose_name='name')),
                ('enabled', models.BooleanField(default=False, verbose_name='Enabled')),
                ('no_nameid_policy', models.BooleanField(default=False, verbose_name='Do not send a nameId Policy')),
                ('requested_name_id_format', models.CharField(default=b'none', max_length=200, verbose_name='Requested NameID format', choices=[(b'username', 'Username (use with Google Apps)'), (b'none', 'None'), (b'persistent', 'Persistent'), (b'transient', 'Transient'), (b'edupersontargetedid', 'Use eduPersonTargetedID attribute'), (b'email', 'Email')])),
                ('transient_is_persistent', models.BooleanField(default=False, verbose_name='This IdP sends a transient NameID but you want a persistent behaviour for your SP')),
                ('persistent_identifier_attribute', models.CharField(max_length=200, null=True, verbose_name='Persistent identifier attribute', blank=True)),
                ('allow_create', models.BooleanField(default=False, verbose_name='Allow IdP to create an identity')),
                ('enable_binding_for_sso_response', models.BooleanField(default=False, verbose_name='Binding for Authnresponse             (taken from metadata by the IdP if not enabled)')),
                ('binding_for_sso_response', models.CharField(default=b'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact', max_length=200, verbose_name='Binding for the SSO responses', choices=[(b'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact', 'Artifact binding'), (b'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'POST binding')])),
                ('enable_http_method_for_slo_request', models.BooleanField(default=False, verbose_name='HTTP method for single logout request             (taken from metadata if not enabled)')),
                ('http_method_for_slo_request', models.IntegerField(default=4, max_length=200, verbose_name='HTTP binding for the SLO requests', choices=[(4, 'Redirect binding'), (5, 'SOAP binding')])),
                ('enable_http_method_for_defederation_request', models.BooleanField(default=False, verbose_name='HTTP method for federation termination request             (taken from metadata if not enabled)')),
                ('http_method_for_defederation_request', models.IntegerField(default=5, max_length=200, verbose_name='HTTP method for the defederation requests', choices=[(4, 'Redirect binding'), (5, 'SOAP binding')])),
                ('force_user_consent', models.BooleanField(default=False, verbose_name='Require the user consent be given at account linking')),
                ('want_force_authn_request', models.BooleanField(default=False, verbose_name='Force authentication')),
                ('want_is_passive_authn_request', models.BooleanField(default=False, verbose_name='Passive authentication')),
                ('want_authn_request_signed', models.BooleanField(default=False, verbose_name='Want AuthnRequest signed')),
                ('handle_persistent', models.CharField(default=b'AUTHSAML2_UNAUTH_PERSISTENT_ACCOUNT_LINKING_BY_AUTH', max_length=200, verbose_name='Behavior with persistent NameID', choices=[(b'AUTHSAML2_UNAUTH_PERSISTENT_ACCOUNT_LINKING_BY_AUTH', 'Account linking by authentication'), (b'AUTHSAML2_UNAUTH_PERSISTENT_CREATE_USER_PSEUDONYMOUS', 'Create new account')])),
                ('handle_transient', models.CharField(default=b'', max_length=200, verbose_name='Behavior with transient NameID', choices=[(b'AUTHSAML2_UNAUTH_TRANSIENT_ASK_AUTH', 'Ask authentication'), (b'AUTHSAML2_UNAUTH_TRANSIENT_OPEN_SESSION', 'Open a session')])),
                ('back_url', models.CharField(default=b'/', max_length=200, verbose_name='Return URL after a successful authentication')),
                ('accept_slo', models.BooleanField(default=True, verbose_name='Accept to receive Single Logout requests')),
                ('forward_slo', models.BooleanField(default=True, verbose_name='Forward Single Logout requests')),
            ],
            options={
                'verbose_name': 'identity provider options policy',
                'verbose_name_plural': 'identity provider options policies',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='KeyValue',
            fields=[
                ('key', models.CharField(max_length=128, serialize=False, primary_key=True)),
                ('value', authentic2.saml.fields.PickledObjectField()),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'key value association',
                'verbose_name_plural': 'key value associations',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertyArtifact',
            fields=[
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('artifact', models.CharField(max_length=128, serialize=False, primary_key=True)),
                ('content', models.TextField()),
                ('provider_id', models.CharField(max_length=256)),
            ],
            options={
                'verbose_name': 'SAML artifact',
                'verbose_name_plural': 'SAML artifacts',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertyFederation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name_id_format', models.CharField(max_length=100, null=True, verbose_name=b'NameIDFormat', blank=True)),
                ('name_id_content', models.CharField(max_length=100, verbose_name=b'NameID')),
                ('name_id_qualifier', models.CharField(max_length=256, null=True, verbose_name=b'NameQualifier', blank=True)),
                ('name_id_sp_name_qualifier', models.CharField(max_length=256, null=True, verbose_name=b'SPNameQualifier', blank=True)),
                ('termination_notified', models.BooleanField(default=False)),
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('last_modification', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'SAML federation',
                'verbose_name_plural': 'SAML federations',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertyManageDump',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('django_session_key', models.CharField(max_length=128)),
                ('manage_dump', models.TextField(blank=True)),
            ],
            options={
                'verbose_name': 'SAML manage dump',
                'verbose_name_plural': 'SAML manage dumps',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertyProvider',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(help_text='Internal nickname for the service provider', max_length=140, blank=True)),
                ('slug', models.SlugField(unique=True, max_length=140)),
                ('entity_id', models.URLField(unique=True)),
                ('entity_id_sha1', models.CharField(max_length=40, blank=True)),
                ('metadata_url', models.URLField(max_length=256, blank=True)),
                ('protocol_conformance', models.IntegerField(max_length=10, choices=[(3, b'SAML 2.0')])),
                ('metadata', models.TextField(validators=[authentic2.saml.models.metadata_validator])),
                ('public_key', models.TextField(blank=True)),
                ('ssl_certificate', models.TextField(blank=True)),
                ('ca_cert_chain', models.TextField(blank=True)),
                ('federation_source', models.CharField(max_length=64, null=True, blank=True)),
            ],
            options={
                'ordering': ('name',),
                'verbose_name': 'SAML provider',
                'verbose_name_plural': 'SAML providers',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertyIdentityProvider',
            fields=[
                ('liberty_provider', models.OneToOneField(related_name='identity_provider', primary_key=True, serialize=False, to='saml.LibertyProvider')),
                ('enabled', models.BooleanField(default=False, verbose_name='Enabled')),
                ('enable_following_idp_options_policy', models.BooleanField(default=False, verbose_name='The following options policy will apply except if a policy for all identity provider is defined.')),
                ('enable_following_authorization_policy', models.BooleanField(default=False, verbose_name='The following authorization policy will apply except if a policy for all identity provider is defined.')),
                ('authorization_policy', models.ForeignKey(related_name='authorization_policy', on_delete=django.db.models.deletion.SET_NULL, verbose_name='authorization identity providers policy', blank=True, to='saml.AuthorizationSPPolicy', null=True)),
                ('idp_options_policy', models.ForeignKey(related_name='idp_options_policy', on_delete=django.db.models.deletion.SET_NULL, verbose_name='identity provider options policy', blank=True, to='saml.IdPOptionsSPPolicy', null=True)),
            ],
            options={
                'verbose_name': 'SAML identity provider',
                'verbose_name_plural': 'SAML identity providers',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertyServiceProvider',
            fields=[
                ('liberty_provider', models.OneToOneField(related_name='service_provider', primary_key=True, serialize=False, to='saml.LibertyProvider')),
                ('enabled', models.BooleanField(default=False, verbose_name='Enabled')),
                ('enable_following_sp_options_policy', models.BooleanField(default=False, verbose_name='The following options policy will apply except if a policy for all service provider is defined.')),
                ('enable_following_attribute_policy', models.BooleanField(default=False, verbose_name='The following attribute policy will apply except if a policy for all service provider is defined.')),
                ('users_can_manage_federations', models.BooleanField(default=True, verbose_name='users can manage federation')),
                ('attribute_policy', models.ForeignKey(related_name='attribute_policy', on_delete=django.db.models.deletion.SET_NULL, verbose_name='attribute policy', blank=True, to='idp.AttributePolicy', null=True)),
            ],
            options={
                'verbose_name': 'SAML service provider',
                'verbose_name_plural': 'SAML service providers',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertySession',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('django_session_key', models.CharField(max_length=128)),
                ('session_index', models.CharField(max_length=80)),
                ('provider_id', models.CharField(max_length=256)),
                ('name_id_qualifier', models.CharField(max_length=256, null=True, verbose_name='Qualifier')),
                ('name_id_format', models.CharField(max_length=100, null=True, verbose_name='NameIDFormat')),
                ('name_id_content', models.CharField(max_length=100, verbose_name='NameID')),
                ('name_id_sp_name_qualifier', models.CharField(max_length=256, null=True, verbose_name='SPNameQualifier')),
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('federation', models.ForeignKey(blank=True, to='saml.LibertyFederation', null=True)),
            ],
            options={
                'verbose_name': 'SAML session',
                'verbose_name_plural': 'SAML sessions',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertySessionDump',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('django_session_key', models.CharField(max_length=128)),
                ('session_dump', models.TextField(blank=True)),
                ('kind', models.IntegerField(choices=[(0, b'sp'), (1, b'idp')])),
            ],
            options={
                'verbose_name': 'SAML session dump',
                'verbose_name_plural': 'SAML session dumps',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LibertySessionSP',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('django_session_key', models.CharField(max_length=128)),
                ('session_index', models.CharField(max_length=80)),
                ('federation', models.ForeignKey(to='saml.LibertyFederation')),
            ],
            options={
                'verbose_name': 'SAML service provider session',
                'verbose_name_plural': 'SAML service provider sessions',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='SAMLAttribute',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('object_id', models.PositiveIntegerField(verbose_name='object identifier')),
                ('name_format', models.CharField(default=b'basic', max_length=64, verbose_name='name format', choices=[(b'basic', b'Basic'), (b'uri', b'URI'), (b'unspecified', b'Unspecified')])),
                ('name', models.CharField(help_text='the local attribute name is used if left blank', max_length=128, verbose_name='name', blank=True)),
                ('friendly_name', models.CharField(max_length=64, verbose_name='friendly name', blank=True)),
                ('attribute_name', models.CharField(max_length=64, verbose_name='attribute name')),
                ('enabled', models.BooleanField(default=True, verbose_name='enabled')),
                ('content_type', models.ForeignKey(verbose_name='content type', to='contenttypes.ContentType')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='SPOptionsIdPPolicy',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=80, verbose_name='name')),
                ('enabled', models.BooleanField(default=False, verbose_name='Enabled')),
                ('prefered_assertion_consumer_binding', models.CharField(default=b'meta', max_length=4, verbose_name='Prefered assertion consumer binding', choices=[(b'meta', 'Use the default from the metadata file'), (b'art', 'Artifact binding'), (b'post', 'POST binding')])),
                ('encrypt_nameid', models.BooleanField(default=False, verbose_name='Encrypt NameID')),
                ('encrypt_assertion', models.BooleanField(default=False, verbose_name='Encrypt Assertion')),
                ('authn_request_signed', models.BooleanField(default=False, verbose_name='Authentication request signed')),
                ('idp_initiated_sso', models.BooleanField(default=False, verbose_name='Allow IdP initiated SSO')),
                ('default_name_id_format', models.CharField(default=b'none', max_length=256, choices=[(b'username', 'Username (use with Google Apps)'), (b'none', 'None'), (b'persistent', 'Persistent'), (b'transient', 'Transient'), (b'edupersontargetedid', 'Use eduPersonTargetedID attribute'), (b'email', 'Email')])),
                ('accepted_name_id_format', authentic2.saml.fields.MultiSelectField(blank=True, max_length=1024, verbose_name='NameID formats accepted', choices=[(b'username', 'Username (use with Google Apps)'), (b'none', 'None'), (b'persistent', 'Persistent'), (b'transient', 'Transient'), (b'edupersontargetedid', 'Use eduPersonTargetedID attribute'), (b'email', 'Email')])),
                ('ask_user_consent', models.BooleanField(default=False, verbose_name='Ask user for consent when creating a federation')),
                ('accept_slo', models.BooleanField(default=True, verbose_name='Accept to receive Single Logout requests')),
                ('forward_slo', models.BooleanField(default=True, verbose_name='Forward Single Logout requests')),
                ('needs_iframe_logout', models.BooleanField(default=False, help_text='logout URL are normally loaded inside an <img> HTML tag, some service provider need to use an iframe', verbose_name='needs iframe logout')),
                ('iframe_logout_timeout', models.PositiveIntegerField(default=300, help_text="if iframe logout is used, it's the time between the onload event for this iframe and the moment we consider its loading to be really finished", verbose_name='iframe logout timeout')),
                ('http_method_for_slo_request', models.IntegerField(default=4, verbose_name='HTTP binding for the SLO requests', choices=[(4, 'Redirect binding'), (5, 'SOAP binding')])),
                ('federation_mode', models.PositiveIntegerField(default=0, verbose_name='federation mode', choices=[(0, 'explicit'), (1, 'implicit')])),
            ],
            options={
                'verbose_name': 'service provider options policy',
                'verbose_name_plural': 'service provider options policies',
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='samlattribute',
            unique_together=set([('content_type', 'object_id', 'name_format', 'name', 'friendly_name', 'attribute_name')]),
        ),
        migrations.AddField(
            model_name='libertyserviceprovider',
            name='sp_options_policy',
            field=models.ForeignKey(related_name='sp_options_policy', on_delete=django.db.models.deletion.SET_NULL, verbose_name='service provider options policy', blank=True, to='saml.SPOptionsIdPPolicy', null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='libertyfederation',
            name='idp',
            field=models.ForeignKey(blank=True, to='saml.LibertyIdentityProvider', null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='libertyfederation',
            name='sp',
            field=models.ForeignKey(blank=True, to='saml.LibertyServiceProvider', null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='libertyfederation',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, blank=True, to='auth.User', null=True),
            preserve_default=True,
        ),
    ]
