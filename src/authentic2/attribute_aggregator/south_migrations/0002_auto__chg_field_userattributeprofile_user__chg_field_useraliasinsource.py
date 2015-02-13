# -*- coding: utf-8 -*-
from south.v2 import SchemaMigration

from authentic2.compat import user_model_label


class Migration(SchemaMigration):
    def forwards(self, orm):
        pass


    def backwards(self, orm):
        pass

    models = {
        'attribute_aggregator.attributesource': {
            'Meta': {'object_name': 'AttributeSource'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'namespace': ('django.db.models.fields.CharField', [], {'default': "('Default', 'Default')", 'max_length': '100'})
        },
        'attribute_aggregator.ldapsource': {
            'Meta': {'object_name': 'LdapSource', '_ormbases': ['attribute_aggregator.AttributeSource']},
            'attributesource_ptr': ('django.db.models.fields.related.OneToOneField', [], {'to': "orm['attribute_aggregator.AttributeSource']", 'unique': 'True', 'primary_key': 'True'}),
            'base': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'certificate': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'is_auth_backend': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'ldaps': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'port': ('django.db.models.fields.IntegerField', [], {'default': '389'}),
            'server': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'user': ('django.db.models.fields.CharField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'})
        },
        'attribute_aggregator.useraliasinsource': {
            'Meta': {'unique_together': "(('name', 'source'),)", 'object_name': 'UserAliasInSource'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['attribute_aggregator.AttributeSource']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'user_alias_in_source'", 'to': "orm['%s']" % user_model_label})
        },
        'attribute_aggregator.userattributeprofile': {
            'Meta': {'object_name': 'UserAttributeProfile'},
            'data': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'blank': 'True', 'related_name': "'user_attribute_profile'", 'unique': 'True', 'null': 'True', 'to': "orm['%s']" % user_model_label})
        },
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
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
        },
        'contenttypes.contenttype': {
            'Meta': {'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        }
    }
    
    complete_apps = ['attribute_aggregator']
