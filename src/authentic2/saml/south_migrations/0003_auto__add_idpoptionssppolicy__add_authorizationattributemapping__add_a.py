# encoding: utf-8
from south.db import db
from south.v2 import SchemaMigration


from authentic2.compat import user_model_label


class Migration(SchemaMigration):
    
    def forwards(self, orm):
        
        # Adding model 'IdPOptionsSPPolicy'
        db.create_table('saml_idpoptionssppolicy', (
            ('http_method_for_slo_request', self.gf('django.db.models.fields.IntegerField')(default=4, max_length=60)),
            ('enable_http_method_for_defederation_request', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=80)),
            ('http_method_for_defederation_request', self.gf('django.db.models.fields.IntegerField')(default=5, max_length=60)),
            ('binding_for_sso_response', self.gf('django.db.models.fields.CharField')(default='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact', max_length=60)),
            ('enabled', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('allow_create', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('want_authn_request_signed', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('enable_http_method_for_slo_request', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('requested_name_id_format', self.gf('django.db.models.fields.CharField')(default='none', max_length=20)),
            ('user_consent', self.gf('django.db.models.fields.CharField')(default='urn:oasis:names:tc:SAML:2.0:consent:current-implicit', max_length=60)),
            ('no_nameid_policy', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('transient_is_persistent', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('want_is_passive_authn_request', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('enable_binding_for_sso_response', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('want_force_authn_request', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
        ))
        db.send_create_signal('saml', ['IdPOptionsSPPolicy'])

        # Adding model 'AuthorizationAttributeMapping'
        db.create_table('saml_authorizationattributemapping', (
            ('map', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['saml.AuthorizationAttributeMap'])),
            ('attribute_name', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('source_attribute_name', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('attribute_value_format', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('attribute_value', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
        ))
        db.send_create_signal('saml', ['AuthorizationAttributeMapping'])

        # Adding model 'AuthorizationSPPolicy'
        db.create_table('saml_authorizationsppolicy', (
            ('ext_function', self.gf('django.db.models.fields.CharField')(max_length=80, blank=True)),
            ('enabled', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True)),
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('attribute_map', self.gf('django.db.models.fields.related.ForeignKey')(blank=True, related_name='authorization_attributes', null=True, to=orm['saml.AuthorizationAttributeMap'])),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=80)),
        ))
        db.send_create_signal('saml', ['AuthorizationSPPolicy'])

        # Adding model 'AuthorizationAttributeMap'
        db.create_table('saml_authorizationattributemap', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=40)),
        ))
        db.send_create_signal('saml', ['AuthorizationAttributeMap'])

        # Changing field 'LibertyServiceProvider.ask_user_consent'
        db.alter_column('saml_libertyserviceprovider', 'ask_user_consent', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyServiceProvider.encrypt_nameid'
        db.alter_column('saml_libertyserviceprovider', 'encrypt_nameid', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyServiceProvider.enabled'
        db.alter_column('saml_libertyserviceprovider', 'enabled', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyServiceProvider.authn_request_signed'
        db.alter_column('saml_libertyserviceprovider', 'authn_request_signed', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyServiceProvider.idp_initiated_sso'
        db.alter_column('saml_libertyserviceprovider', 'idp_initiated_sso', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyServiceProvider.encrypt_assertion'
        db.alter_column('saml_libertyserviceprovider', 'encrypt_assertion', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Deleting field 'LibertyIdentityProvider.enable_http_method_for_defederation_request'
        db.delete_column('saml_libertyidentityprovider', 'enable_http_method_for_defederation_request')

        # Deleting field 'LibertyIdentityProvider.want_force_authn_request'
        db.delete_column('saml_libertyidentityprovider', 'want_force_authn_request')

        # Deleting field 'LibertyIdentityProvider.http_method_for_defederation_request'
        db.delete_column('saml_libertyidentityprovider', 'http_method_for_defederation_request')

        # Deleting field 'LibertyIdentityProvider.binding_for_sso_response'
        db.delete_column('saml_libertyidentityprovider', 'binding_for_sso_response')

        # Deleting field 'LibertyIdentityProvider.allow_create'
        db.delete_column('saml_libertyidentityprovider', 'allow_create')

        # Deleting field 'LibertyIdentityProvider.enable_http_method_for_slo_request'
        db.delete_column('saml_libertyidentityprovider', 'enable_http_method_for_slo_request')

        # Deleting field 'LibertyIdentityProvider.requested_name_id_format'
        db.delete_column('saml_libertyidentityprovider', 'requested_name_id_format')

        # Deleting field 'LibertyIdentityProvider.attribute_map'
        db.delete_column('saml_libertyidentityprovider', 'attribute_map_id')

        # Deleting field 'LibertyIdentityProvider.user_consent'
        db.delete_column('saml_libertyidentityprovider', 'user_consent')

        # Deleting field 'LibertyIdentityProvider.no_nameid_policy'
        db.delete_column('saml_libertyidentityprovider', 'no_nameid_policy')

        # Deleting field 'LibertyIdentityProvider.http_method_for_slo_request'
        db.delete_column('saml_libertyidentityprovider', 'http_method_for_slo_request')

        # Deleting field 'LibertyIdentityProvider.want_authn_request_signed'
        db.delete_column('saml_libertyidentityprovider', 'want_authn_request_signed')

        # Deleting field 'LibertyIdentityProvider.want_is_passive_authn_request'
        db.delete_column('saml_libertyidentityprovider', 'want_is_passive_authn_request')

        # Deleting field 'LibertyIdentityProvider.enable_binding_for_sso_response'
        db.delete_column('saml_libertyidentityprovider', 'enable_binding_for_sso_response')

        # Deleting field 'LibertyIdentityProvider.enable_following_policy'
        db.delete_column('saml_libertyidentityprovider', 'enable_following_policy')

        # Adding field 'LibertyIdentityProvider.idp_options_policy'
        db.add_column('saml_libertyidentityprovider', 'idp_options_policy', self.gf('django.db.models.fields.related.ForeignKey')(blank=True, related_name='idp_options_policy', null=True, to=orm['saml.IdPOptionsSPPolicy']), keep_default=False)

        # Adding field 'LibertyIdentityProvider.enable_following_idp_options_policy'
        db.add_column('saml_libertyidentityprovider', 'enable_following_idp_options_policy', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True), keep_default=False)

        # Adding field 'LibertyIdentityProvider.enable_following_authorization_policy'
        db.add_column('saml_libertyidentityprovider', 'enable_following_authorization_policy', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True), keep_default=False)

        # Adding field 'LibertyIdentityProvider.authorization_policy'
        db.add_column('saml_libertyidentityprovider', 'authorization_policy', self.gf('django.db.models.fields.related.ForeignKey')(blank=True, related_name='authorization_policy', null=True, to=orm['saml.AuthorizationSPPolicy']), keep_default=False)

        # Changing field 'LibertyIdentityProvider.enabled'
        db.alter_column('saml_libertyidentityprovider', 'enabled', self.gf('django.db.models.fields.BooleanField')(blank=True))
    
    
    def backwards(self, orm):
        
        # Deleting model 'IdPOptionsSPPolicy'
        db.delete_table('saml_idpoptionssppolicy')

        # Deleting model 'AuthorizationAttributeMapping'
        db.delete_table('saml_authorizationattributemapping')

        # Deleting model 'AuthorizationSPPolicy'
        db.delete_table('saml_authorizationsppolicy')

        # Deleting model 'AuthorizationAttributeMap'
        db.delete_table('saml_authorizationattributemap')

        # Changing field 'LibertyServiceProvider.ask_user_consent'
        db.alter_column('saml_libertyserviceprovider', 'ask_user_consent', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyServiceProvider.encrypt_nameid'
        db.alter_column('saml_libertyserviceprovider', 'encrypt_nameid', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyServiceProvider.enabled'
        db.alter_column('saml_libertyserviceprovider', 'enabled', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyServiceProvider.authn_request_signed'
        db.alter_column('saml_libertyserviceprovider', 'authn_request_signed', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyServiceProvider.idp_initiated_sso'
        db.alter_column('saml_libertyserviceprovider', 'idp_initiated_sso', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyServiceProvider.encrypt_assertion'
        db.alter_column('saml_libertyserviceprovider', 'encrypt_assertion', self.gf('django.db.models.fields.BooleanField')())

        # Adding field 'LibertyIdentityProvider.enable_http_method_for_defederation_request'
        db.add_column('saml_libertyidentityprovider', 'enable_http_method_for_defederation_request', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyIdentityProvider.want_force_authn_request'
        db.add_column('saml_libertyidentityprovider', 'want_force_authn_request', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyIdentityProvider.http_method_for_defederation_request'
        db.add_column('saml_libertyidentityprovider', 'http_method_for_defederation_request', self.gf('django.db.models.fields.IntegerField')(default=5, max_length=60), keep_default=False)

        # Adding field 'LibertyIdentityProvider.binding_for_sso_response'
        db.add_column('saml_libertyidentityprovider', 'binding_for_sso_response', self.gf('django.db.models.fields.CharField')(default='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact', max_length=60), keep_default=False)

        # Adding field 'LibertyIdentityProvider.allow_create'
        db.add_column('saml_libertyidentityprovider', 'allow_create', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyIdentityProvider.enable_http_method_for_slo_request'
        db.add_column('saml_libertyidentityprovider', 'enable_http_method_for_slo_request', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyIdentityProvider.requested_name_id_format'
        db.add_column('saml_libertyidentityprovider', 'requested_name_id_format', self.gf('django.db.models.fields.CharField')(default='none', max_length=20), keep_default=False)

        # Adding field 'LibertyIdentityProvider.attribute_map'
        db.add_column('saml_libertyidentityprovider', 'attribute_map', self.gf('django.db.models.fields.related.ForeignKey')(related_name='identity_providers', null=True, to=orm['saml.LibertyAttributeMap'], blank=True), keep_default=False)

        # Adding field 'LibertyIdentityProvider.user_consent'
        db.add_column('saml_libertyidentityprovider', 'user_consent', self.gf('django.db.models.fields.CharField')(default='urn:oasis:names:tc:SAML:2.0:consent:current-implicit', max_length=60), keep_default=False)

        # Adding field 'LibertyIdentityProvider.no_nameid_policy'
        db.add_column('saml_libertyidentityprovider', 'no_nameid_policy', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyIdentityProvider.http_method_for_slo_request'
        db.add_column('saml_libertyidentityprovider', 'http_method_for_slo_request', self.gf('django.db.models.fields.IntegerField')(default=4, max_length=60), keep_default=False)

        # Adding field 'LibertyIdentityProvider.want_authn_request_signed'
        db.add_column('saml_libertyidentityprovider', 'want_authn_request_signed', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyIdentityProvider.want_is_passive_authn_request'
        db.add_column('saml_libertyidentityprovider', 'want_is_passive_authn_request', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyIdentityProvider.enable_binding_for_sso_response'
        db.add_column('saml_libertyidentityprovider', 'enable_binding_for_sso_response', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyIdentityProvider.enable_following_policy'
        db.add_column('saml_libertyidentityprovider', 'enable_following_policy', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Deleting field 'LibertyIdentityProvider.idp_options_policy'
        db.delete_column('saml_libertyidentityprovider', 'idp_options_policy_id')

        # Deleting field 'LibertyIdentityProvider.enable_following_idp_options_policy'
        db.delete_column('saml_libertyidentityprovider', 'enable_following_idp_options_policy')

        # Deleting field 'LibertyIdentityProvider.enable_following_authorization_policy'
        db.delete_column('saml_libertyidentityprovider', 'enable_following_authorization_policy')

        # Deleting field 'LibertyIdentityProvider.authorization_policy'
        db.delete_column('saml_libertyidentityprovider', 'authorization_policy_id')

        # Changing field 'LibertyIdentityProvider.enabled'
        db.alter_column('saml_libertyidentityprovider', 'enabled', self.gf('django.db.models.fields.BooleanField')())
    
    
    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        'auth.permission': {
            'Meta': {'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'blank': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        'contenttypes.contenttype': {
            'Meta': {'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'saml.authorizationattributemap': {
            'Meta': {'object_name': 'AuthorizationAttributeMap'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '40'})
        },
        'saml.authorizationattributemapping': {
            'Meta': {'object_name': 'AuthorizationAttributeMapping'},
            'attribute_name': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'attribute_value': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'attribute_value_format': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'map': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['saml.AuthorizationAttributeMap']"}),
            'source_attribute_name': ('django.db.models.fields.CharField', [], {'max_length': '40'})
        },
        'saml.authorizationsppolicy': {
            'Meta': {'object_name': 'AuthorizationSPPolicy'},
            'attribute_map': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'authorization_attributes'", 'null': 'True', 'to': "orm['saml.AuthorizationAttributeMap']"}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'ext_function': ('django.db.models.fields.CharField', [], {'max_length': '80', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'})
        },
        'saml.idpoptionssppolicy': {
            'Meta': {'object_name': 'IdPOptionsSPPolicy'},
            'allow_create': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'binding_for_sso_response': ('django.db.models.fields.CharField', [], {'default': "'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'", 'max_length': '60'}),
            'enable_binding_for_sso_response': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enable_http_method_for_defederation_request': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enable_http_method_for_slo_request': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'http_method_for_defederation_request': ('django.db.models.fields.IntegerField', [], {'default': '5', 'max_length': '60'}),
            'http_method_for_slo_request': ('django.db.models.fields.IntegerField', [], {'default': '4', 'max_length': '60'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'no_nameid_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'requested_name_id_format': ('django.db.models.fields.CharField', [], {'default': "'none'", 'max_length': '20'}),
            'transient_is_persistent': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'user_consent': ('django.db.models.fields.CharField', [], {'default': "'urn:oasis:names:tc:SAML:2.0:consent:current-implicit'", 'max_length': '60'}),
            'want_authn_request_signed': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'want_force_authn_request': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'want_is_passive_authn_request': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'})
        },
        'saml.keyvalue': {
            'Meta': {'object_name': 'KeyValue'},
            'key': ('django.db.models.fields.CharField', [], {'max_length': '40', 'primary_key': 'True'}),
            'value': ('authentic2.saml.fields.PickledObjectField', [], {})
        },
        'saml.libertyartifact': {
            'Meta': {'object_name': 'LibertyArtifact'},
            'artifact': ('django.db.models.fields.CharField', [], {'max_length': '40', 'primary_key': 'True'}),
            'content': ('django.db.models.fields.TextField', [], {}),
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'provider_id': ('django.db.models.fields.CharField', [], {'max_length': '80'})
        },
        'saml.libertyassertion': {
            'Meta': {'object_name': 'LibertyAssertion'},
            'assertion': ('django.db.models.fields.TextField', [], {}),
            'assertion_id': ('django.db.models.fields.CharField', [], {'max_length': '50'}),
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'provider_id': ('django.db.models.fields.CharField', [], {'max_length': '80'}),
            'session_index': ('django.db.models.fields.CharField', [], {'max_length': '80'})
        },
        'saml.libertyattributemap': {
            'Meta': {'object_name': 'LibertyAttributeMap'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '40'})
        },
        'saml.libertyattributemapping': {
            'Meta': {'object_name': 'LibertyAttributeMapping'},
            'attribute_name': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'attribute_value_format': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'map': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['saml.LibertyAttributeMap']"}),
            'source_attribute_name': ('django.db.models.fields.CharField', [], {'max_length': '40'})
        },
        'saml.libertyfederation': {
            'Meta': {'unique_together': "(('name_id_qualifier', 'name_id_format', 'name_id_content', 'name_id_sp_name_qualifier'),)", 'object_name': 'LibertyFederation'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'idp_id': ('django.db.models.fields.CharField', [], {'max_length': '80'}),
            'name_id_content': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name_id_format': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True', 'blank': 'True'}),
            'name_id_qualifier': ('django.db.models.fields.CharField', [], {'max_length': '150', 'null': 'True', 'blank': 'True'}),
            'name_id_sp_name_qualifier': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True', 'blank': 'True'}),
            'name_id_sp_provided_id': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True', 'blank': 'True'}),
            'sp_id': ('django.db.models.fields.CharField', [], {'max_length': '80'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['%s']" % user_model_label})
        },
        'saml.libertyidentitydump': {
            'Meta': {'object_name': 'LibertyIdentityDump'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'identity_dump': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['%s']" % user_model_label, 'unique': 'True'})
        },
        'saml.libertyidentityprovider': {
            'Meta': {'object_name': 'LibertyIdentityProvider'},
            'authorization_policy': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'authorization_policy'", 'null': 'True', 'to': "orm['saml.AuthorizationSPPolicy']"}),
            'enable_following_authorization_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enable_following_idp_options_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'idp_options_policy': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'idp_options_policy'", 'null': 'True', 'to': "orm['saml.IdPOptionsSPPolicy']"}),
            'liberty_provider': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'identity_provider'", 'unique': 'True', 'primary_key': 'True', 'to': "orm['saml.LibertyProvider']"})
        },
        'saml.libertymanagedump': {
            'Meta': {'object_name': 'LibertyManageDump'},
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'manage_dump': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        'saml.libertyprovider': {
            'Meta': {'object_name': 'LibertyProvider'},
            'ca_cert_chain': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'entity_id': ('django.db.models.fields.URLField', [], {'unique': 'True', 'max_length': '200'}),
            'entity_id_sha1': ('django.db.models.fields.CharField', [], {'max_length': '40', 'blank': 'True'}),
            'federation_source': ('django.db.models.fields.CharField', [], {'max_length': '64', 'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'metadata': ('django.db.models.fields.TextField', [], {}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '40', 'blank': 'True'}),
            'protocol_conformance': ('django.db.models.fields.IntegerField', [], {'max_length': '10'}),
            'public_key': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'ssl_certificate': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        'saml.libertyserviceprovider': {
            'Meta': {'object_name': 'LibertyServiceProvider'},
            'accepted_name_id_format': ('authentic2.saml.fields.MultiSelectField', [], {'max_length': '31', 'blank': 'True'}),
            'ask_user_consent': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'attribute_map': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'service_providers'", 'null': 'True', 'to': "orm['saml.LibertyAttributeMap']"}),
            'authn_request_signed': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'default_name_id_format': ('django.db.models.fields.CharField', [], {'default': "'none'", 'max_length': '20'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'encrypt_assertion': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'encrypt_nameid': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'idp_initiated_sso': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'liberty_provider': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'service_provider'", 'unique': 'True', 'primary_key': 'True', 'to': "orm['saml.LibertyProvider']"}),
            'prefered_assertion_consumer_binding': ('django.db.models.fields.CharField', [], {'default': "'meta'", 'max_length': '4'})
        },
        'saml.libertysession': {
            'Meta': {'object_name': 'LibertySession'},
            'assertion': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['saml.LibertyAssertion']", 'null': 'True'}),
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'federation': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['saml.LibertyFederation']", 'null': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name_id_content': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name_id_format': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True'}),
            'name_id_qualifier': ('django.db.models.fields.CharField', [], {'max_length': '150', 'null': 'True'}),
            'name_id_sp_name_qualifier': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True'}),
            'provider_id': ('django.db.models.fields.CharField', [], {'max_length': '80'}),
            'session_index': ('django.db.models.fields.CharField', [], {'max_length': '80'})
        },
        'saml.libertysessiondump': {
            'Meta': {'object_name': 'LibertySessionDump'},
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'session_dump': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        'saml.libertysessionsp': {
            'Meta': {'object_name': 'LibertySessionSP'},
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'federation': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['saml.LibertyFederation']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'session_index': ('django.db.models.fields.CharField', [], {'max_length': '80'})
        }
    }
    
    complete_apps = ['saml']
