# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


from authentic2.compat import user_model_label


class Migration(SchemaMigration):

    def forwards(self, orm):

        # Changing field 'LibertySession.django_session_key'
        db.alter_column(u'saml_libertysession', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=128))

        # Changing field 'LibertyArtifact.provider_id'
        db.alter_column(u'saml_libertyartifact', 'provider_id', self.gf('django.db.models.fields.CharField')(max_length=256))

        # Changing field 'LibertyArtifact.artifact'
        db.alter_column(u'saml_libertyartifact', 'artifact', self.gf('django.db.models.fields.CharField')(max_length=128, primary_key=True))

        # Changing field 'LibertyArtifact.django_session_key'
        db.alter_column(u'saml_libertyartifact', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=128))

        # Changing field 'LibertyManageDump.django_session_key'
        db.alter_column(u'saml_libertymanagedump', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=128))

        # Changing field 'LibertySessionSP.django_session_key'
        db.alter_column(u'saml_libertysessionsp', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=128))

        # Changing field 'LibertyAssertion.provider_id'
        db.alter_column(u'saml_libertyassertion', 'provider_id', self.gf('django.db.models.fields.CharField')(max_length=256))

        # Changing field 'LibertyAssertion.assertion_id'
        db.alter_column(u'saml_libertyassertion', 'assertion_id', self.gf('django.db.models.fields.CharField')(max_length=128))

        # Changing field 'LibertyAssertion.session_index'
        db.alter_column(u'saml_libertyassertion', 'session_index', self.gf('django.db.models.fields.CharField')(max_length=128))

        # Changing field 'LibertySessionDump.django_session_key'
        db.alter_column(u'saml_libertysessiondump', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=128))

    def backwards(self, orm):

        # Changing field 'LibertySession.django_session_key'
        db.alter_column(u'saml_libertysession', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=40))

        # Changing field 'LibertyArtifact.provider_id'
        db.alter_column(u'saml_libertyartifact', 'provider_id', self.gf('django.db.models.fields.CharField')(max_length=80))

        # Changing field 'LibertyArtifact.artifact'
        db.alter_column(u'saml_libertyartifact', 'artifact', self.gf('django.db.models.fields.CharField')(max_length=40, primary_key=True))

        # Changing field 'LibertyArtifact.django_session_key'
        db.alter_column(u'saml_libertyartifact', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=40))

        # Changing field 'LibertyManageDump.django_session_key'
        db.alter_column(u'saml_libertymanagedump', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=40))

        # Changing field 'LibertySessionSP.django_session_key'
        db.alter_column(u'saml_libertysessionsp', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=40))

        # Changing field 'LibertyAssertion.provider_id'
        db.alter_column(u'saml_libertyassertion', 'provider_id', self.gf('django.db.models.fields.CharField')(max_length=80))

        # Changing field 'LibertyAssertion.assertion_id'
        db.alter_column(u'saml_libertyassertion', 'assertion_id', self.gf('django.db.models.fields.CharField')(max_length=50))

        # Changing field 'LibertyAssertion.session_index'
        db.alter_column(u'saml_libertyassertion', 'session_index', self.gf('django.db.models.fields.CharField')(max_length=80))

        # Changing field 'LibertySessionDump.django_session_key'
        db.alter_column(u'saml_libertysessiondump', 'django_session_key', self.gf('django.db.models.fields.CharField')(max_length=40))

    models = {
        u'attribute_aggregator.attributesource': {
            'Meta': {'object_name': 'AttributeSource'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'})
        },
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
        },
        u'idp.attributeitem': {
            'Meta': {'object_name': 'AttributeItem'},
            'attribute_name': ('django.db.models.fields.CharField', [], {'default': "('OpenLDAProotDSE', 'OpenLDAProotDSE')", 'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'output_name_format': ('django.db.models.fields.CharField', [], {'default': "('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', 'SAMLv2 URI')", 'max_length': '100'}),
            'output_namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'}),
            'required': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
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
            'allow_attributes_selection': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'ask_consent_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'attribute_filter_for_sso_from_push_sources': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'filter attributes of push sources with list'", 'null': 'True', 'to': u"orm['idp.AttributeList']"}),
            'attribute_list_for_sso_from_pull_sources': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'attributes from pull sources'", 'null': 'True', 'to': u"orm['idp.AttributeList']"}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'filter_source_of_filtered_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'forward_attributes_from_push_sources': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'map_attributes_from_push_sources': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'map_attributes_of_filtered_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'output_name_format': ('django.db.models.fields.CharField', [], {'default': "('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', 'SAMLv2 URI')", 'max_length': '100'}),
            'output_namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'}),
            'send_error_and_no_attrs_if_missing_required_attrs': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
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
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'})
        },
        u'saml.idpoptionssppolicy': {
            'Meta': {'object_name': 'IdPOptionsSPPolicy'},
            'accept_slo': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'allow_create': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'back_url': ('django.db.models.fields.CharField', [], {'default': "'/'", 'max_length': '200'}),
            'binding_for_sso_response': ('django.db.models.fields.CharField', [], {'default': "'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'", 'max_length': '200'}),
            'enable_binding_for_sso_response': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enable_http_method_for_defederation_request': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enable_http_method_for_slo_request': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'force_user_consent': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'forward_slo': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'handle_persistent': ('django.db.models.fields.CharField', [], {'default': "'AUTHSAML2_UNAUTH_PERSISTENT_ACCOUNT_LINKING_BY_AUTH'", 'max_length': '200'}),
            'handle_transient': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '200'}),
            'http_method_for_defederation_request': ('django.db.models.fields.IntegerField', [], {'default': '5', 'max_length': '200'}),
            'http_method_for_slo_request': ('django.db.models.fields.IntegerField', [], {'default': '4', 'max_length': '200'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'no_nameid_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'requested_name_id_format': ('django.db.models.fields.CharField', [], {'default': "'none'", 'max_length': '200'}),
            'transient_is_persistent': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'want_authn_request_signed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'want_force_authn_request': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'want_is_passive_authn_request': ('django.db.models.fields.BooleanField', [], {'default': 'False'})
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
            'django_session_key': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
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
            'Meta': {'unique_together': "(('name_id_qualifier', 'name_id_format', 'name_id_content', 'name_id_sp_name_qualifier'),)", 'object_name': 'LibertyFederation'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'idp_id': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            'name_id_content': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name_id_format': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True', 'blank': 'True'}),
            'name_id_qualifier': ('django.db.models.fields.CharField', [], {'max_length': '256', 'null': 'True', 'blank': 'True'}),
            'name_id_sp_name_qualifier': ('django.db.models.fields.CharField', [], {'max_length': '256', 'null': 'True', 'blank': 'True'}),
            'name_id_sp_provided_id': ('django.db.models.fields.CharField', [], {'max_length': '256', 'null': 'True', 'blank': 'True'}),
            'sp_id': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % user_model_label})
        },
        u'saml.libertyidentitydump': {
            'Meta': {'object_name': 'LibertyIdentityDump'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'identity_dump': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % user_model_label, 'unique': 'True'})
        },
        u'saml.libertyidentityprovider': {
            'Meta': {'object_name': 'LibertyIdentityProvider'},
            'authorization_policy': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'authorization_policy'", 'null': 'True', 'to': u"orm['saml.AuthorizationSPPolicy']"}),
            'enable_following_authorization_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enable_following_idp_options_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
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
            'enable_following_attribute_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enable_following_sp_options_policy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
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
            'accept_slo': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'accepted_name_id_format': ('authentic2.saml.fields.MultiSelectField', [], {'max_length': '31', 'blank': 'True'}),
            'ask_user_consent': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'authn_request_signed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'default_name_id_format': ('django.db.models.fields.CharField', [], {'default': "'none'", 'max_length': '200'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'encrypt_assertion': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'encrypt_nameid': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'forward_slo': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'idp_initiated_sso': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'prefered_assertion_consumer_binding': ('django.db.models.fields.CharField', [], {'default': "'meta'", 'max_length': '4'})
        }
    }

    complete_apps = ['saml']
