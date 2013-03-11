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

        # Changing field 'UserAttributeProfile.user'
        db.alter_column(u'attribute_aggregator_userattributeprofile', 'user_id', self.gf('django.db.models.fields.related.OneToOneField')(unique=True, null=True, to=orm['authentic2.User']))

        # Changing field 'UserAliasInSource.user'
        db.alter_column(u'attribute_aggregator_useraliasinsource', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['authentic2.User']))

    def backwards(self, orm):

        # Changing field 'UserAttributeProfile.user'
        db.alter_column(u'attribute_aggregator_userattributeprofile', 'user_id', self.gf('django.db.models.fields.related.OneToOneField')(unique=True, null=True, to=orm['auth.User']))

        # Changing field 'UserAliasInSource.user'
        db.alter_column(u'attribute_aggregator_useraliasinsource', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User']))

    models = {
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
            'user': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'user_alias_in_source'", 'to': u"orm['authentic2.User']"})
        },
        u'attribute_aggregator.userattributeprofile': {
            'Meta': {'object_name': 'UserAttributeProfile'},
            'data': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'blank': 'True', 'related_name': "'user_attribute_profile'", 'unique': 'True', 'null': 'True', 'to': u"orm['authentic2.User']"})
        },
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

    complete_apps = ['attribute_aggregator']
