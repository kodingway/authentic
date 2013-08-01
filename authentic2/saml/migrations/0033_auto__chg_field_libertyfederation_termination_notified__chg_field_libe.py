# encoding: utf-8
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models

class Migration(SchemaMigration):
    
    def forwards(self, orm):
        
        # Changing field 'LibertyFederation.termination_notified'
        db.alter_column(u'saml_libertyfederation', 'termination_notified', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyFederation.user'
        db.alter_column(u'saml_libertyfederation', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth2_user.User'], null=True, blank=True))

        # Changing field 'LibertyServiceProvider.enable_following_sp_options_policy'
        db.alter_column(u'saml_libertyserviceprovider', 'enable_following_sp_options_policy', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyServiceProvider.enabled'
        db.alter_column(u'saml_libertyserviceprovider', 'enabled', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyServiceProvider.enable_following_attribute_policy'
        db.alter_column(u'saml_libertyserviceprovider', 'enable_following_attribute_policy', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Adding field 'IdPOptionsSPPolicy.persistent_identifier_attribute'
        db.add_column(u'saml_idpoptionssppolicy', 'persistent_identifier_attribute', self.gf('django.db.models.fields.CharField')(max_length=200, null=True, blank=True), keep_default=False)

        # Changing field 'IdPOptionsSPPolicy.transient_is_persistent'
        db.alter_column(u'saml_idpoptionssppolicy', 'transient_is_persistent', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.enable_http_method_for_slo_request'
        db.alter_column(u'saml_idpoptionssppolicy', 'enable_http_method_for_slo_request', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.forward_slo'
        db.alter_column(u'saml_idpoptionssppolicy', 'forward_slo', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.want_force_authn_request'
        db.alter_column(u'saml_idpoptionssppolicy', 'want_force_authn_request', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.allow_create'
        db.alter_column(u'saml_idpoptionssppolicy', 'allow_create', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.force_user_consent'
        db.alter_column(u'saml_idpoptionssppolicy', 'force_user_consent', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.want_is_passive_authn_request'
        db.alter_column(u'saml_idpoptionssppolicy', 'want_is_passive_authn_request', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.enable_http_method_for_defederation_request'
        db.alter_column(u'saml_idpoptionssppolicy', 'enable_http_method_for_defederation_request', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.enabled'
        db.alter_column(u'saml_idpoptionssppolicy', 'enabled', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.no_nameid_policy'
        db.alter_column(u'saml_idpoptionssppolicy', 'no_nameid_policy', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.want_authn_request_signed'
        db.alter_column(u'saml_idpoptionssppolicy', 'want_authn_request_signed', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.enable_binding_for_sso_response'
        db.alter_column(u'saml_idpoptionssppolicy', 'enable_binding_for_sso_response', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'IdPOptionsSPPolicy.accept_slo'
        db.alter_column(u'saml_idpoptionssppolicy', 'accept_slo', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyIdentityProvider.enabled'
        db.alter_column(u'saml_libertyidentityprovider', 'enabled', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyIdentityProvider.enable_following_idp_options_policy'
        db.alter_column(u'saml_libertyidentityprovider', 'enable_following_idp_options_policy', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'LibertyIdentityProvider.enable_following_authorization_policy'
        db.alter_column(u'saml_libertyidentityprovider', 'enable_following_authorization_policy', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'AuthorizationSPPolicy.enabled'
        db.alter_column(u'saml_authorizationsppolicy', 'enabled', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'SPOptionsIdPPolicy.ask_user_consent'
        db.alter_column(u'saml_spoptionsidppolicy', 'ask_user_consent', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'SPOptionsIdPPolicy.encrypt_nameid'
        db.alter_column(u'saml_spoptionsidppolicy', 'encrypt_nameid', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'SPOptionsIdPPolicy.enabled'
        db.alter_column(u'saml_spoptionsidppolicy', 'enabled', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'SPOptionsIdPPolicy.authn_request_signed'
        db.alter_column(u'saml_spoptionsidppolicy', 'authn_request_signed', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'SPOptionsIdPPolicy.forward_slo'
        db.alter_column(u'saml_spoptionsidppolicy', 'forward_slo', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'SPOptionsIdPPolicy.idp_initiated_sso'
        db.alter_column(u'saml_spoptionsidppolicy', 'idp_initiated_sso', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'SPOptionsIdPPolicy.encrypt_assertion'
        db.alter_column(u'saml_spoptionsidppolicy', 'encrypt_assertion', self.gf('django.db.models.fields.BooleanField')(blank=True))

        # Changing field 'SPOptionsIdPPolicy.accept_slo'
        db.alter_column(u'saml_spoptionsidppolicy', 'accept_slo', self.gf('django.db.models.fields.BooleanField')(blank=True))
    
    
    def backwards(self, orm):
        
        # Changing field 'LibertyFederation.termination_notified'
        db.alter_column(u'saml_libertyfederation', 'termination_notified', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyFederation.user'
        db.alter_column(u'saml_libertyfederation', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True, on_delete=models.SET_NULL, blank=True))

        # Changing field 'LibertyServiceProvider.enable_following_sp_options_policy'
        db.alter_column(u'saml_libertyserviceprovider', 'enable_following_sp_options_policy', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyServiceProvider.enabled'
        db.alter_column(u'saml_libertyserviceprovider', 'enabled', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyServiceProvider.enable_following_attribute_policy'
        db.alter_column(u'saml_libertyserviceprovider', 'enable_following_attribute_policy', self.gf('django.db.models.fields.BooleanField')())

        # Deleting field 'IdPOptionsSPPolicy.persistent_identifier_attribute'
        db.delete_column(u'saml_idpoptionssppolicy', 'persistent_identifier_attribute')

        # Changing field 'IdPOptionsSPPolicy.transient_is_persistent'
        db.alter_column(u'saml_idpoptionssppolicy', 'transient_is_persistent', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.enable_http_method_for_slo_request'
        db.alter_column(u'saml_idpoptionssppolicy', 'enable_http_method_for_slo_request', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.forward_slo'
        db.alter_column(u'saml_idpoptionssppolicy', 'forward_slo', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.want_force_authn_request'
        db.alter_column(u'saml_idpoptionssppolicy', 'want_force_authn_request', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.allow_create'
        db.alter_column(u'saml_idpoptionssppolicy', 'allow_create', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.force_user_consent'
        db.alter_column(u'saml_idpoptionssppolicy', 'force_user_consent', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.want_is_passive_authn_request'
        db.alter_column(u'saml_idpoptionssppolicy', 'want_is_passive_authn_request', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.enable_http_method_for_defederation_request'
        db.alter_column(u'saml_idpoptionssppolicy', 'enable_http_method_for_defederation_request', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.enabled'
        db.alter_column(u'saml_idpoptionssppolicy', 'enabled', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.no_nameid_policy'
        db.alter_column(u'saml_idpoptionssppolicy', 'no_nameid_policy', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.want_authn_request_signed'
        db.alter_column(u'saml_idpoptionssppolicy', 'want_authn_request_signed', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.enable_binding_for_sso_response'
        db.alter_column(u'saml_idpoptionssppolicy', 'enable_binding_for_sso_response', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'IdPOptionsSPPolicy.accept_slo'
        db.alter_column(u'saml_idpoptionssppolicy', 'accept_slo', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyIdentityProvider.enabled'
        db.alter_column(u'saml_libertyidentityprovider', 'enabled', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyIdentityProvider.enable_following_idp_options_policy'
        db.alter_column(u'saml_libertyidentityprovider', 'enable_following_idp_options_policy', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'LibertyIdentityProvider.enable_following_authorization_policy'
        db.alter_column(u'saml_libertyidentityprovider', 'enable_following_authorization_policy', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'AuthorizationSPPolicy.enabled'
        db.alter_column(u'saml_authorizationsppolicy', 'enabled', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'SPOptionsIdPPolicy.ask_user_consent'
        db.alter_column(u'saml_spoptionsidppolicy', 'ask_user_consent', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'SPOptionsIdPPolicy.encrypt_nameid'
        db.alter_column(u'saml_spoptionsidppolicy', 'encrypt_nameid', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'SPOptionsIdPPolicy.enabled'
        db.alter_column(u'saml_spoptionsidppolicy', 'enabled', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'SPOptionsIdPPolicy.authn_request_signed'
        db.alter_column(u'saml_spoptionsidppolicy', 'authn_request_signed', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'SPOptionsIdPPolicy.forward_slo'
        db.alter_column(u'saml_spoptionsidppolicy', 'forward_slo', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'SPOptionsIdPPolicy.idp_initiated_sso'
        db.alter_column(u'saml_spoptionsidppolicy', 'idp_initiated_sso', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'SPOptionsIdPPolicy.encrypt_assertion'
        db.alter_column(u'saml_spoptionsidppolicy', 'encrypt_assertion', self.gf('django.db.models.fields.BooleanField')())

        # Changing field 'SPOptionsIdPPolicy.accept_slo'
        db.alter_column(u'saml_spoptionsidppolicy', 'accept_slo', self.gf('django.db.models.fields.BooleanField')())
    
    
    models = {
        u'attribute_aggregator.attributesource': {
            'Meta': {'object_name': 'AttributeSource'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'})
        },
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        u'auth2_user.user': {
            'Meta': {'object_name': 'User', 'db_table': "'authentic2_user'"},
            'backend': ('django.db.models.fields.CharField', [], {'max_length': '64', 'blank': 'True'}),
            'backend_id': ('django.db.models.fields.CharField', [], {'max_length': '256', 'blank': 'True'}),
            'company': ('django.db.models.fields.CharField', [], {'max_length': '50', 'blank': 'True'}),
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2013, 7, 30, 10, 20, 56, 311194)'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '128', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '64', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'blank': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2013, 7, 30, 10, 20, 56, 310949)'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '64', 'blank': 'True'}),
            'nickname': ('django.db.models.fields.CharField', [], {'max_length': '50', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'phone': ('django.db.models.fields.CharField', [], {'max_length': '50', 'blank': 'True'}),
            'postal_address': ('django.db.models.fields.TextField', [], {'max_length': '255', 'blank': 'True'}),
            'url': ('django.db.models.fields.URLField', [], {'max_length': '200', 'blank': 'True'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '256'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'idp.attributeitem': {
            'Meta': {'object_name': 'AttributeItem'},
            'attribute_name': ('django.db.models.fields.CharField', [], {'default': "('OpenLDAProotDSE', 'OpenLDAProotDSE')", 'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'output_name_format': ('django.db.models.fields.CharField', [], {'default': "('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', 'SAMLv2 URI')", 'max_length': '100'}),
            'output_namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'}),
            'required': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['attribute_aggregator.AttributeSource']", 'null': 'True', 'blank': 'True'})
        },
        u'idp.attributelist': {
            'Meta': {'object_name': 'AttributeList'},
            'attributes': ('django.db.models.fields.related.ManyToManyField', [], {'blank': 'True', 'related_name': "'attributes of the list'", 'null': 'True', 'symmetrical': 'False', 'to': u"orm['idp.AttributeItem']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'})
        },
        u'idp.attributepolicy': {
            'Meta': {'object_name': 'AttributePolicy'},
            'allow_attributes_selection': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'blank': 'True'}),
            'ask_consent_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'blank': 'True'}),
            'attribute_filter_for_sso_from_push_sources': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'filter attributes of push sources with list'", 'null': 'True', 'to': u"orm['idp.AttributeList']"}),
            'attribute_list_for_sso_from_pull_sources': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'attributes from pull sources'", 'null': 'True', 'to': u"orm['idp.AttributeList']"}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'filter_source_of_filtered_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'forward_attributes_from_push_sources': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'map_attributes_from_push_sources': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'map_attributes_of_filtered_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'output_name_format': ('django.db.models.fields.CharField', [], {'default': "('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', 'SAMLv2 URI')", 'max_length': '100'}),
            'output_namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'}),
            'send_error_and_no_attrs_if_missing_required_attrs': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'source_filter_for_sso_from_push_sources': ('django.db.models.fields.related.ManyToManyField', [], {'blank': 'True', 'related_name': "'filter attributes of push sources with sources'", 'null': 'True', 'symmetrical': 'False', 'to': u"orm['attribute_aggregator.AttributeSource']"})
        },
        u'saml.authorizationattributemap': {
            'Meta': {'object_name': 'AuthorizationAttributeMap'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '40'})
        },
        u'saml.authorizationattributemapping': {
            'Meta': {'object_name': 'AuthorizationAttributeMapping'},
            'attribute_name': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'attribute_value': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'attribute_value_format': ('django.db.models.fields.CharField', [], {'max_length': '40', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'map': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['saml.AuthorizationAttributeMap']"}),
            'source_attribute_name': ('django.db.models.fields.CharField', [], {'max_length': '40', 'blank': 'True'})
        },
        u'saml.authorizationsppolicy': {
            'Meta': {'object_name': 'AuthorizationSPPolicy'},
            'attribute_map': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'authorization_attributes'", 'null': 'True', 'to': u"orm['saml.AuthorizationAttributeMap']"}),
            'default_denial_message': ('django.db.models.fields.CharField', [], {'default': "u'You are not authorized to access the service.'", 'max_length': '80'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'})
        },
        u'saml.idpoptionssppolicy': {
            'Meta': {'object_name': 'IdPOptionsSPPolicy'},
            'accept_slo': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'blank': 'True'}),
            'allow_create': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'back_url': ('django.db.models.fields.CharField', [], {'default': "'/'", 'max_length': '200'}),
            'binding_for_sso_response': ('django.db.models.fields.CharField', [], {'default': "'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'", 'max_length': '200'}),
            'enable_binding_for_sso_response': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enable_http_method_for_defederation_request': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enable_http_method_for_slo_request': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'force_user_consent': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'forward_slo': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'blank': 'True'}),
            'handle_persistent': ('django.db.models.fields.CharField', [], {'default': "'AUTHSAML2_UNAUTH_PERSISTENT_ACCOUNT_LINKING_BY_AUTH'", 'max_length': '200'}),
            'handle_transient': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '200'}),
            'http_method_for_defederation_request': ('django.db.models.fields.IntegerField', [], {'default': '5', 'max_length': '200'}),
            'http_method_for_slo_request': ('django.db.models.fields.IntegerField', [], {'default': '4', 'max_length': '200'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'no_nameid_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'persistent_identifier_attribute': ('django.db.models.fields.CharField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'requested_name_id_format': ('django.db.models.fields.CharField', [], {'default': "'none'", 'max_length': '200'}),
            'transient_is_persistent': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'want_authn_request_signed': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'want_force_authn_request': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'want_is_passive_authn_request': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'})
        },
        u'saml.keyvalue': {
            'Meta': {'object_name': 'KeyValue'},
            'key': ('django.db.models.fields.CharField', [], {'max_length': '128', 'primary_key': 'True'}),
            'value': ('authentic2.saml.fields.PickledObjectField', [], {})
        },
        u'saml.libertyartifact': {
            'Meta': {'object_name': 'LibertyArtifact'},
            'artifact': ('django.db.models.fields.CharField', [], {'max_length': '128', 'primary_key': 'True'}),
            'content': ('django.db.models.fields.TextField', [], {}),
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'provider_id': ('django.db.models.fields.CharField', [], {'max_length': '256'})
        },
        u'saml.libertyassertion': {
            'Meta': {'object_name': 'LibertyAssertion'},
            'assertion': ('django.db.models.fields.TextField', [], {}),
            'assertion_id': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'provider_id': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            'session_index': ('django.db.models.fields.CharField', [], {'max_length': '128'})
        },
        u'saml.libertyfederation': {
            'Meta': {'object_name': 'LibertyFederation'},
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'idp': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['saml.LibertyIdentityProvider']", 'null': 'True'}),
            'last_modification': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'name_id_content': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name_id_format': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True', 'blank': 'True'}),
            'sp': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['saml.LibertyServiceProvider']", 'null': 'True'}),
            'termination_notified': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth2_user.User']", 'null': 'True', 'blank': 'True'})
        },
        u'saml.libertyidentityprovider': {
            'Meta': {'object_name': 'LibertyIdentityProvider'},
            'authorization_policy': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'authorization_policy'", 'null': 'True', 'to': u"orm['saml.AuthorizationSPPolicy']"}),
            'enable_following_authorization_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enable_following_idp_options_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'idp_options_policy': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'idp_options_policy'", 'null': 'True', 'to': u"orm['saml.IdPOptionsSPPolicy']"}),
            'liberty_provider': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'identity_provider'", 'unique': 'True', 'primary_key': 'True', 'to': u"orm['saml.LibertyProvider']"})
        },
        u'saml.libertymanagedump': {
            'Meta': {'object_name': 'LibertyManageDump'},
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'manage_dump': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        u'saml.libertyprovider': {
            'Meta': {'object_name': 'LibertyProvider'},
            'ca_cert_chain': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'entity_id': ('django.db.models.fields.URLField', [], {'unique': 'True', 'max_length': '200'}),
            'entity_id_sha1': ('django.db.models.fields.CharField', [], {'max_length': '40', 'blank': 'True'}),
            'federation_source': ('django.db.models.fields.CharField', [], {'max_length': '64', 'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'metadata': ('django.db.models.fields.TextField', [], {}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '140', 'blank': 'True'}),
            'protocol_conformance': ('django.db.models.fields.IntegerField', [], {'max_length': '10'}),
            'public_key': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'ssl_certificate': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        u'saml.libertyproviderpolicy': {
            'Meta': {'object_name': 'LibertyProviderPolicy'},
            'authn_request_signature_check_hint': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'})
        },
        u'saml.libertyserviceprovider': {
            'Meta': {'object_name': 'LibertyServiceProvider'},
            'attribute_policy': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'attribute_policy'", 'null': 'True', 'to': u"orm['idp.AttributePolicy']"}),
            'enable_following_attribute_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enable_following_sp_options_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'liberty_provider': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'service_provider'", 'unique': 'True', 'primary_key': 'True', 'to': u"orm['saml.LibertyProvider']"}),
            'policy': ('django.db.models.fields.related.ForeignKey', [], {'default': '1', 'to': u"orm['saml.LibertyProviderPolicy']", 'null': 'True'}),
            'sp_options_policy': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'sp_options_policy'", 'null': 'True', 'to': u"orm['saml.SPOptionsIdPPolicy']"})
        },
        u'saml.libertysession': {
            'Meta': {'object_name': 'LibertySession'},
            'assertion': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['saml.LibertyAssertion']", 'null': 'True'}),
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'federation': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['saml.LibertyFederation']", 'null': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name_id_content': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name_id_format': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True'}),
            'name_id_qualifier': ('django.db.models.fields.CharField', [], {'max_length': '256', 'null': 'True'}),
            'name_id_sp_name_qualifier': ('django.db.models.fields.CharField', [], {'max_length': '256', 'null': 'True'}),
            'provider_id': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            'session_index': ('django.db.models.fields.CharField', [], {'max_length': '80'})
        },
        u'saml.libertysessiondump': {
            'Meta': {'object_name': 'LibertySessionDump'},
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'kind': ('django.db.models.fields.IntegerField', [], {}),
            'session_dump': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        u'saml.libertysessionsp': {
            'Meta': {'object_name': 'LibertySessionSP'},
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'federation': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['saml.LibertyFederation']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'session_index': ('django.db.models.fields.CharField', [], {'max_length': '80'})
        },
        u'saml.spoptionsidppolicy': {
            'Meta': {'object_name': 'SPOptionsIdPPolicy'},
            'accept_slo': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'blank': 'True'}),
            'accepted_name_id_format': ('authentic2.saml.fields.MultiSelectField', [], {'max_length': '1024', 'blank': 'True'}),
            'ask_user_consent': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'authn_request_signed': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'default_name_id_format': ('django.db.models.fields.CharField', [], {'default': "'none'", 'max_length': '256'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'encrypt_assertion': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'encrypt_nameid': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'forward_slo': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'idp_initiated_sso': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'prefered_assertion_consumer_binding': ('django.db.models.fields.CharField', [], {'default': "'meta'", 'max_length': '4'})
        }
    }
    
    complete_apps = ['saml']
