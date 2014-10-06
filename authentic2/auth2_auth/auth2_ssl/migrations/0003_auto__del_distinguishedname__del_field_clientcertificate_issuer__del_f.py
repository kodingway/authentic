# -*- coding: utf-8 -*-
from south.db import db
from south.v2 import SchemaMigration

from authentic2.compat import user_model_label


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Deleting model 'DistinguishedName'
        db.delete_table(u'auth2_ssl_distinguishedname')

        # Deleting field 'ClientCertificate.issuer'
        db.delete_column(u'auth2_ssl_clientcertificate', 'issuer_id')

        # Deleting field 'ClientCertificate.subject'
        db.delete_column(u'auth2_ssl_clientcertificate', 'subject_id')

        # Adding field 'ClientCertificate.subject_dn'
        db.add_column(u'auth2_ssl_clientcertificate', 'subject_dn',
                      self.gf('django.db.models.fields.CharField')(default='broken', max_length=255),
                      keep_default=False)

        # Adding field 'ClientCertificate.issuer_dn'
        db.add_column(u'auth2_ssl_clientcertificate', 'issuer_dn',
                      self.gf('django.db.models.fields.CharField')(default='broken', max_length=255),
                      keep_default=False)


    def backwards(self, orm):
        # Adding model 'DistinguishedName'
        db.create_table(u'auth2_ssl_distinguishedname', (
            ('cn', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('uid', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('c', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('d', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('g', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('i', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('l', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('o', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('st', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('s', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('t', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('ou', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
            ('email', self.gf('django.db.models.fields.CharField')(max_length=255, blank=True)),
        ))
        db.send_create_signal('auth2_ssl', ['DistinguishedName'])

        # Adding field 'ClientCertificate.issuer'
        db.add_column(u'auth2_ssl_clientcertificate', 'issuer',
                      self.gf('django.db.models.fields.related.ForeignKey')(related_name='issuer', null=True, to=orm['auth2_ssl.DistinguishedName'], blank=True),
                      keep_default=False)

        # Adding field 'ClientCertificate.subject'
        db.add_column(u'auth2_ssl_clientcertificate', 'subject',
                      self.gf('django.db.models.fields.related.ForeignKey')(related_name='subject', null=True, to=orm['auth2_ssl.DistinguishedName'], blank=True),
                      keep_default=False)

        # Deleting field 'ClientCertificate.subject_dn'
        db.delete_column(u'auth2_ssl_clientcertificate', 'subject_dn')

        # Deleting field 'ClientCertificate.issuer_dn'
        db.delete_column(u'auth2_ssl_clientcertificate', 'issuer_dn')


    models = {
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
        },
        u'auth2_ssl.clientcertificate': {
            'Meta': {'object_name': 'ClientCertificate'},
            'cert': ('django.db.models.fields.TextField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer_dn': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'serial': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'subject_dn': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
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

    complete_apps = ['auth2_ssl']
