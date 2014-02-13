# -*- coding: utf-8 -*-
from south.db import db
from south.v2 import SchemaMigration

from authentic2.compat import user_model_label

class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'AuthenticationEvent'
        db.create_table(u'authentic2_authenticationevent', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('when', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('who', self.gf('django.db.models.fields.CharField')(max_length=80)),
            ('how', self.gf('django.db.models.fields.CharField')(max_length=10)),
            ('nonce', self.gf('django.db.models.fields.CharField')(max_length=255)),
        ))
        db.send_create_signal(u'authentic2', ['AuthenticationEvent'])


    def backwards(self, orm):
        # Deleting model 'AuthenticationEvent'
        db.delete_table(u'authentic2_authenticationevent')


    models = {
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'ordering': "(u'content_type__app_label', u'content_type__model', u'codename')", 'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        user_model_label: {
            'Meta': {'object_name':  user_model_label.split('.')[-1]},
        },
        u'authentic2.authenticationevent': {
            'Meta': {'object_name': 'AuthenticationEvent'},
            'how': ('django.db.models.fields.CharField', [], {'max_length': '10'}),
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
        u'authentic2.userexternalid': {
            'Meta': {'object_name': 'UserExternalId'},
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'external_id': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'source': ('django.db.models.fields.URLField', [], {'max_length': '256'}),
            'updated': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
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
