# -*- coding: utf-8 -*-
from south.v2 import SchemaMigration

from authentic2.compat import user_model_label

class Migration(SchemaMigration):
    depends_on = (
            ('idp', '0011_auto__del_attributelist__del_attributeitem__chg_field_attributepolicy_.py'),
    )

    def forwards(self, orm):
        pass


    def backwards(self, orm):
        pass


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
        u'attribute_aggregator.ldapsource': {
            'Meta': {'object_name': 'LdapSource', '_ormbases': [u'attribute_aggregator.AttributeSource']},
            u'attributesource_ptr': ('django.db.models.fields.related.OneToOneField', [], {'to': u"orm['attribute_aggregator.AttributeSource']", 'unique': 'True', 'primary_key': 'True'}),
            'base': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'certificate': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'is_auth_backend': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'ldaps': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'port': ('django.db.models.fields.IntegerField', [], {'default': '389'}),
            'server': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'user': ('django.db.models.fields.CharField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'})
        },
        u'attribute_aggregator.useraliasinsource': {
            'Meta': {'unique_together': "(('name', 'source'),)", 'object_name': 'UserAliasInSource'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['attribute_aggregator.AttributeSource']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'user_alias_in_source'", 'to': u"orm['%s']" % user_model_label})
        },
        u'attribute_aggregator.userattributeprofile': {
            'Meta': {'object_name': 'UserAttributeProfile'},
            'data': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'blank': 'True', 'related_name': "'user_attribute_profile'", 'unique': 'True', 'null': 'True', 'to': u"orm['%s']" % user_model_label})
        },
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        }
    }

    complete_apps = ['attribute_aggregator']
