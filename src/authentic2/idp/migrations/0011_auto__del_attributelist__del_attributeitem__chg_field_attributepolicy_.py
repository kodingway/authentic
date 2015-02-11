# -*- coding: utf-8 -*-
from south.db import db
from south.v2 import SchemaMigration

class Migration(SchemaMigration):

    def forwards(self, orm):
        # Rename model 'AttributeList' table
        db.rename_table('idp_attributelist', 'attribute_aggregator_attributelist')
        db.send_create_signal('attribute_aggregator', ['AttributeList'])

        # Rename M2M table for field attributes on 'AttributeList'
        db.rename_table(db.shorten_name('idp_attributelist_attributes'),
                db.shorten_name('attribute_aggregator_attributelist_attributes'))

        # Rename model 'AttributeItem' table
        db.rename_table('idp_attributeitem', 'attribute_aggregator_attributeitem')
        db.send_create_signal('attribute_aggregator', ['AttributeItem'])


        # Changing field 'AttributePolicy.attribute_filter_for_sso_from_push_sources'
        db.alter_column(u'idp_attributepolicy', 'attribute_filter_for_sso_from_push_sources_id', self.gf('django.db.models.fields.related.ForeignKey')(null=True, to=orm['attribute_aggregator.AttributeList']))

        # Changing field 'AttributePolicy.attribute_list_for_sso_from_pull_sources'
        db.alter_column(u'idp_attributepolicy', 'attribute_list_for_sso_from_pull_sources_id', self.gf('django.db.models.fields.related.ForeignKey')(null=True, to=orm['attribute_aggregator.AttributeList']))

    def backwards(self, orm):
        # Rename model 'AttributeList' table
        db.rename_table('attribute_aggregator_attributelist', 'idp_attributelist', )
        db.send_create_signal('idp', ['AttributeList'])


        # Rename M2M table for field attributes on 'AttributeList'
        db.rename_table(
                db.shorten_name('attribute_aggregator_attributelist_attributes'),
                db.shorten_name('idp_attributelist_attributes'))

        # Deleting model 'AttributeItem' table
        db.rename_table('attribute_aggregator_attributeitem',
                'idp_attributeitem')
        db.send_create_signal('idp', ['AttributeItem'])


        # Changing field 'AttributePolicy.attribute_filter_for_sso_from_push_sources'
        db.alter_column(u'idp_attributepolicy', 'attribute_filter_for_sso_from_push_sources_id', self.gf('django.db.models.fields.related.ForeignKey')(null=True, to=orm['idp.AttributeList']))

        # Changing field 'AttributePolicy.attribute_list_for_sso_from_pull_sources'
        db.alter_column(u'idp_attributepolicy', 'attribute_list_for_sso_from_pull_sources_id', self.gf('django.db.models.fields.related.ForeignKey')(null=True, to=orm['idp.AttributeList']))

    models = {
        u'attribute_aggregator.attributeitem': {
            'Meta': {'object_name': 'AttributeItem'},
            'attribute_name': ('django.db.models.fields.CharField', [], {'default': "('OpenLDAProotDSE', 'OpenLDAProotDSE')", 'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'output_name_format': ('django.db.models.fields.CharField', [], {'default': "('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', 'SAMLv2 URI')", 'max_length': '100'}),
            'output_namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'}),
            'required': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['attribute_aggregator.AttributeSource']", 'null': 'True', 'blank': 'True'})
        },
        u'attribute_aggregator.attributelist': {
            'Meta': {'object_name': 'AttributeList'},
            'attributes': ('django.db.models.fields.related.ManyToManyField', [], {'blank': 'True', 'related_name': "'attributes of the list'", 'null': 'True', 'symmetrical': 'False', 'to': u"orm['attribute_aggregator.AttributeItem']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'})
        },
        u'attribute_aggregator.attributesource': {
            'Meta': {'object_name': 'AttributeSource'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'})
        },
        u'idp.attributepolicy': {
            'Meta': {'object_name': 'AttributePolicy'},
            'allow_attributes_selection': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'ask_consent_attributes': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'attribute_filter_for_sso_from_push_sources': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'filter attributes of push sources with list'", 'null': 'True', 'to': u"orm['attribute_aggregator.AttributeList']"}),
            'attribute_list_for_sso_from_pull_sources': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'attributes from pull sources'", 'null': 'True', 'to': u"orm['attribute_aggregator.AttributeList']"}),
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
        }
    }

    complete_apps = ['idp']
