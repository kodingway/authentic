# encoding: utf-8
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


from authentic2.compat import user_model_label



class Migration(SchemaMigration):

    def forwards(self, orm):
        
        # Adding model 'SPOptionsIdPPolicy'
        db.create_table('saml_spoptionsidppolicy', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=80)),
            ('prefered_assertion_consumer_binding', self.gf('django.db.models.fields.CharField')(default='meta', max_length=4)),
            ('encrypt_nameid', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('encrypt_assertion', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('authn_request_signed', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('idp_initiated_sso', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('default_name_id_format', self.gf('django.db.models.fields.CharField')(default='none', max_length=20)),
            ('accepted_name_id_format', self.gf('authentic2.saml.fields.MultiSelectField')(max_length=31, blank=True)),
            ('ask_user_consent', self.gf('django.db.models.fields.BooleanField')(default=False)),
        ))
        db.send_create_signal('saml', ['SPOptionsIdPPolicy'])

        # Deleting field 'LibertyServiceProvider.prefered_assertion_consumer_binding'
        db.delete_column('saml_libertyserviceprovider', 'prefered_assertion_consumer_binding')

        # Deleting field 'LibertyServiceProvider.ask_user_consent'
        db.delete_column('saml_libertyserviceprovider', 'ask_user_consent')

        # Deleting field 'LibertyServiceProvider.encrypt_nameid'
        db.delete_column('saml_libertyserviceprovider', 'encrypt_nameid')

        # Deleting field 'LibertyServiceProvider.authn_request_signed'
        db.delete_column('saml_libertyserviceprovider', 'authn_request_signed')

        # Deleting field 'LibertyServiceProvider.idp_initiated_sso'
        db.delete_column('saml_libertyserviceprovider', 'idp_initiated_sso')

        # Deleting field 'LibertyServiceProvider.encrypt_assertion'
        db.delete_column('saml_libertyserviceprovider', 'encrypt_assertion')

        # Deleting field 'LibertyServiceProvider.accepted_name_id_format'
        db.delete_column('saml_libertyserviceprovider', 'accepted_name_id_format')

        # Deleting field 'LibertyServiceProvider.default_name_id_format'
        db.delete_column('saml_libertyserviceprovider', 'default_name_id_format')

        # Adding field 'LibertyServiceProvider.enable_following_sp_options_policy'
        db.add_column('saml_libertyserviceprovider', 'enable_following_sp_options_policy', self.gf('django.db.models.fields.BooleanField')(default=False), keep_default=False)

        # Adding field 'LibertyServiceProvider.sp_options_policy'
        db.add_column('saml_libertyserviceprovider', 'sp_options_policy', self.gf('django.db.models.fields.related.ForeignKey')(blank=True, related_name='sp_options_policy', null=True, to=orm['saml.SPOptionsIdPPolicy']), keep_default=False)


    def backwards(self, orm):
        
        # Deleting model 'SPOptionsIdPPolicy'
        db.delete_table('saml_spoptionsidppolicy')

        # Adding field 'LibertyServiceProvider.prefered_assertion_consumer_binding'
        db.add_column('saml_libertyserviceprovider', 'prefered_assertion_consumer_binding', self.gf('django.db.models.fields.CharField')(default='meta', max_length=4), keep_default=False)

        # Adding field 'LibertyServiceProvider.ask_user_consent'
        db.add_column('saml_libertyserviceprovider', 'ask_user_consent', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True), keep_default=False)

        # Adding field 'LibertyServiceProvider.encrypt_nameid'
        db.add_column('saml_libertyserviceprovider', 'encrypt_nameid', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True), keep_default=False)

        # Adding field 'LibertyServiceProvider.authn_request_signed'
        db.add_column('saml_libertyserviceprovider', 'authn_request_signed', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True), keep_default=False)

        # Adding field 'LibertyServiceProvider.idp_initiated_sso'
        db.add_column('saml_libertyserviceprovider', 'idp_initiated_sso', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True), keep_default=False)

        # Adding field 'LibertyServiceProvider.encrypt_assertion'
        db.add_column('saml_libertyserviceprovider', 'encrypt_assertion', self.gf('django.db.models.fields.BooleanField')(default=False, blank=True), keep_default=False)

        # Adding field 'LibertyServiceProvider.accepted_name_id_format'
        db.add_column('saml_libertyserviceprovider', 'accepted_name_id_format', self.gf('authentic2.saml.fields.MultiSelectField')(default=0, max_length=31, blank=True), keep_default=False)

        # Adding field 'LibertyServiceProvider.default_name_id_format'
        db.add_column('saml_libertyserviceprovider', 'default_name_id_format', self.gf('django.db.models.fields.CharField')(default='none', max_length=20), keep_default=False)

        # Deleting field 'LibertyServiceProvider.enable_following_sp_options_policy'
        db.delete_column('saml_libertyserviceprovider', 'enable_following_sp_options_policy')

        # Deleting field 'LibertyServiceProvider.sp_options_policy'
        db.delete_column('saml_libertyserviceprovider', 'sp_options_policy_id')


    models = {
        'attribute_aggregator.attributesource': {
            'Meta': {'object_name': 'AttributeSource'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'})
        },
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
        },
        'idp.attributeitem': {
            'Meta': {'object_name': 'AttributeItem'},
            'attribute_name': ('django.db.models.fields.CharField', [], {'default': "('OpenLDAProotDSE', 'OpenLDAProotDSE')", 'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'output_name_format': ('django.db.models.fields.CharField', [], {'default': "('urn:oasis:names:tc:SAML:2.0:attrname-format:basic', 'SAMLv2 BASIC')", 'max_length': '100'}),
            'output_namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'}),
            'required': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['attribute_aggregator.AttributeSource']", 'null': 'True', 'blank': 'True'})
        },
        'idp.attributelist': {
            'Meta': {'object_name': 'AttributeList'},
            'attributes': ('django.db.models.fields.related.ManyToManyField', [], {'blank': 'True', 'related_name': "'attributes of the list'", 'null': 'True', 'symmetrical': 'False', 'to': "orm['idp.AttributeItem']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'})
        },
        'idp.attributepolicy': {
            'Meta': {'object_name': 'AttributePolicy'},
            'attribute_filter_for_sso_from_push_sources': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'filter attributes of push sources with list'", 'null': 'True', 'to': "orm['idp.AttributeList']"}),
            'attribute_list_for_sso_from_pull_sources': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'attributes from pull sources'", 'null': 'True', 'to': "orm['idp.AttributeList']"}),
            'filter_source_of_filtered_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'forward_attributes_from_push_sources': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'map_attributes_from_push_sources': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'map_attributes_of_filtered_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'output_name_format': ('django.db.models.fields.CharField', [], {'default': "('urn:oasis:names:tc:SAML:2.0:attrname-format:basic', 'SAMLv2 BASIC')", 'max_length': '100'}),
            'output_namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'}),
            'send_error_and_no_attrs_if_missing_required_attrs': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'source_filter_for_sso_from_push_sources': ('django.db.models.fields.related.ManyToManyField', [], {'blank': 'True', 'related_name': "'filter attributes of push sources with sources'", 'null': 'True', 'symmetrical': 'False', 'to': "orm['attribute_aggregator.AttributeSource']"})
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
            'attribute_value_format': ('django.db.models.fields.CharField', [], {'max_length': '40', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'map': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['saml.AuthorizationAttributeMap']"}),
            'source_attribute_name': ('django.db.models.fields.CharField', [], {'max_length': '40', 'blank': 'True'})
        },
        'saml.authorizationsppolicy': {
            'Meta': {'object_name': 'AuthorizationSPPolicy'},
            'attribute_map': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'authorization_attributes'", 'null': 'True', 'to': "orm['saml.AuthorizationAttributeMap']"}),
            'default_denial_message': ('django.db.models.fields.CharField', [], {'default': "u'You are not authorized to access the service.'", 'max_length': '80'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'})
        },
        'saml.idpoptionssppolicy': {
            'Meta': {'object_name': 'IdPOptionsSPPolicy'},
            'allow_create': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'binding_for_sso_response': ('django.db.models.fields.CharField', [], {'default': "'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'", 'max_length': '60'}),
            'enable_binding_for_sso_response': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enable_http_method_for_defederation_request': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enable_http_method_for_slo_request': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'http_method_for_defederation_request': ('django.db.models.fields.IntegerField', [], {'default': '5', 'max_length': '60'}),
            'http_method_for_slo_request': ('django.db.models.fields.IntegerField', [], {'default': '4', 'max_length': '60'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'no_nameid_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'requested_name_id_format': ('django.db.models.fields.CharField', [], {'default': "'none'", 'max_length': '20'}),
            'transient_is_persistent': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'user_consent': ('django.db.models.fields.CharField', [], {'default': "'urn:oasis:names:tc:SAML:2.0:consent:current-implicit'", 'max_length': '60'}),
            'want_authn_request_signed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'want_force_authn_request': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'want_is_passive_authn_request': ('django.db.models.fields.BooleanField', [], {'default': 'False'})
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
            'enable_following_authorization_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enable_following_idp_options_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
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
            'name': ('django.db.models.fields.CharField', [], {'max_length': '140', 'blank': 'True'}),
            'protocol_conformance': ('django.db.models.fields.IntegerField', [], {'max_length': '10'}),
            'public_key': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'ssl_certificate': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        'saml.libertyproviderpolicy': {
            'Meta': {'object_name': 'LibertyProviderPolicy'},
            'authn_request_signature_check_hint': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'})
        },
        'saml.libertyserviceprovider': {
            'Meta': {'object_name': 'LibertyServiceProvider'},
            'attribute_policy': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['idp.AttributePolicy']", 'null': 'True', 'blank': 'True'}),
            'enable_following_sp_options_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'liberty_provider': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'service_provider'", 'unique': 'True', 'primary_key': 'True', 'to': "orm['saml.LibertyProvider']"}),
            'policy': ('django.db.models.fields.related.ForeignKey', [], {'default': '1', 'to': "orm['saml.LibertyProviderPolicy']", 'null': 'True'}),
            'sp_options_policy': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'sp_options_policy'", 'null': 'True', 'to': "orm['saml.SPOptionsIdPPolicy']"})
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
            'kind': ('django.db.models.fields.IntegerField', [], {}),
            'session_dump': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        'saml.libertysessionsp': {
            'Meta': {'object_name': 'LibertySessionSP'},
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'federation': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['saml.LibertyFederation']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'session_index': ('django.db.models.fields.CharField', [], {'max_length': '80'})
        },
        'saml.spoptionsidppolicy': {
            'Meta': {'object_name': 'SPOptionsIdPPolicy'},
            'accepted_name_id_format': ('authentic2.saml.fields.MultiSelectField', [], {'max_length': '31', 'blank': 'True'}),
            'ask_user_consent': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'authn_request_signed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'default_name_id_format': ('django.db.models.fields.CharField', [], {'default': "'none'", 'max_length': '20'}),
            'encrypt_assertion': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'encrypt_nameid': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'idp_initiated_sso': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'prefered_assertion_consumer_binding': ('django.db.models.fields.CharField', [], {'default': "'meta'", 'max_length': '4'})
        }
    }

    complete_apps = ['saml']
