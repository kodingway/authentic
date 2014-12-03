# -*- coding: utf-8 -*-
from south.db import db
from south.v2 import SchemaMigration

from authentic2.compat import user_model_label


class Migration(SchemaMigration):

    def forwards(self, orm):

        # Changing field 'AuthenticationEvent.how'
        db.alter_column(u'authentic2_authenticationevent', 'how', self.gf('django.db.models.fields.CharField')(max_length=32))

    def backwards(self, orm):

        # Changing field 'AuthenticationEvent.how'
        db.alter_column(u'authentic2_authenticationevent', 'how', self.gf('django.db.models.fields.CharField')(max_length=10))

    models = {
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
        },
        u'authentic2.attribute': {
            'Meta': {'object_name': 'Attribute'},
            'asked_on_registration': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'description': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'kind': ('django.db.models.fields.CharField', [], {'max_length': '16'}),
            'label': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '63'}),
            'multiple': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'name': ('django.db.models.fields.SlugField', [], {'unique': 'True', 'max_length': '256'}),
            'required': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'user_editable': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'user_visible': ('django.db.models.fields.BooleanField', [], {'default': 'False'})
        },
        u'authentic2.attributevalue': {
            'Meta': {'object_name': 'AttributeValue'},
            'attribute': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['authentic2.Attribute']"}),
            'content': ('django.db.models.fields.TextField', [], {}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'object_id': ('django.db.models.fields.PositiveIntegerField', [], {})
        },
        u'authentic2.authenticationevent': {
            'Meta': {'object_name': 'AuthenticationEvent'},
            'how': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'nonce': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'when': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'who': ('django.db.models.fields.CharField', [], {'max_length': '80'})
        },
        u'authentic2.deleteduser': {
            'Meta': {'object_name': 'DeletedUser'},
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % user_model_label})
        },
        u'authentic2.federatedid': {
            'Meta': {'object_name': 'FederatedId'},
            'about': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'id_format': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'id_value': ('django.db.models.fields.TextField', [], {}),
            'provider': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'service': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        },
        u'authentic2.logouturl': {
            'Meta': {'object_name': 'LogoutUrl'},
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'logout_url': ('django.db.models.fields.URLField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'logout_use_iframe': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'logout_use_iframe_timeout': ('django.db.models.fields.PositiveIntegerField', [], {'default': '300'}),
            'object_id': ('django.db.models.fields.PositiveIntegerField', [], {})
        },
        u'authentic2.userexternalid': {
            'Meta': {'object_name': 'UserExternalId'},
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'external_id': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'source': ('django.db.models.fields.URLField', [], {'max_length': '256'}),
            'updated': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % user_model_label})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        }
    }

    complete_apps = ['authentic2']
