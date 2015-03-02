# -*- coding: utf-8 -*-
from south.db import db
from south.v2 import SchemaMigration
from ..migration_utils import was_applied


class Migration(SchemaMigration):

    def forwards(self, orm):
        if was_applied(__file__, 'idp_openid'):
            return

        # Changing field 'Nonce.server_url'
        db.alter_column(u'idp_openid_nonce', 'server_url', self.gf('django.db.models.fields.CharField')(max_length=768))

        # Changing field 'Association.issued'
        db.alter_column(u'idp_openid_association', 'issued', self.gf('django.db.models.fields.DateTimeField')())

        # Changing field 'Association.server_url'
        db.alter_column(u'idp_openid_association', 'server_url', self.gf('django.db.models.fields.CharField')(max_length=768))

    def backwards(self, orm):

        # Changing field 'Nonce.server_url'
        db.alter_column(u'idp_openid_nonce', 'server_url', self.gf('django.db.models.fields.CharField')(max_length=2047))

        # Changing field 'Association.issued'
        db.alter_column(u'idp_openid_association', 'issued', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True))

        # Changing field 'Association.server_url'
        db.alter_column(u'idp_openid_association', 'server_url', self.gf('django.db.models.fields.CharField')(max_length=2047))

    models = {
        u'authentic2_idp_openid.association': {
            'Meta': {'unique_together': "(('server_url', 'handle'),)", 'object_name': 'Association'},
            'assoc_type': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'expire': ('django.db.models.fields.DateTimeField', [], {}),
            'handle': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issued': ('django.db.models.fields.DateTimeField', [], {}),
            'lifetime': ('django.db.models.fields.IntegerField', [], {}),
            'secret': ('authentic2.saml.fields.PickledObjectField', [], {}),
            'server_url': ('django.db.models.fields.CharField', [], {'max_length': '768'})
        },
        u'authentic2_idp_openid.nonce': {
            'Meta': {'unique_together': "(('server_url', 'salt'),)", 'object_name': 'Nonce'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'salt': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'server_url': ('django.db.models.fields.CharField', [], {'max_length': '768'}),
            'timestamp': ('django.db.models.fields.IntegerField', [], {})
        },
        u'authentic2_idp_openid.trustedroot': {
            'Meta': {'object_name': 'TrustedRoot'},
            'choices': ('authentic2.saml.fields.PickledObjectField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'trust_root': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'user': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        }
    }

    complete_apps = ['authentic2_idp_openid']
