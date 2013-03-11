# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):
    depends_on = (
            ('authentic2', '0003_auto__add_user'),
    )

    def forwards(self, orm):

        # Changing field 'ClientCertificate.user'
        db.alter_column(u'auth2_ssl_clientcertificate', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['authentic2.User']))

    def backwards(self, orm):

        # Changing field 'ClientCertificate.user'
        db.alter_column(u'auth2_ssl_clientcertificate', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User']))

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
        u'auth2_ssl.clientcertificate': {
            'Meta': {'object_name': 'ClientCertificate'},
            'cert': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'issuer'", 'null': 'True', 'to': u"orm['auth2_ssl.DistinguishedName']"}),
            'serial': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'subject': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'subject'", 'null': 'True', 'to': u"orm['auth2_ssl.DistinguishedName']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['authentic2.User']"})
        },
        u'auth2_ssl.distinguishedname': {
            'Meta': {'object_name': 'DistinguishedName'},
            'c': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'cn': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'd': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'email': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'g': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'i': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'l': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'o': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'ou': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            's': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'st': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            't': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'uid': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'})
        },
        u'authentic2.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        }
    }

    complete_apps = ['auth2_ssl']
