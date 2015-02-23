# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Service'
        db.create_table(u'authentic2_idp_cas_service', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('logout_url', self.gf('django.db.models.fields.URLField')(max_length=255, null=True, blank=True)),
            ('logout_use_iframe', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('logout_use_iframe_timeout', self.gf('django.db.models.fields.PositiveIntegerField')(default=300)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=128)),
            ('slug', self.gf('django.db.models.fields.SlugField')(unique=True, max_length=128)),
            ('urls', self.gf('django.db.models.fields.TextField')(max_length=128)),
            ('identifier_attribute', self.gf('django.db.models.fields.CharField')(max_length=64)),
        ))
        db.send_create_signal(u'authentic2_idp_cas', ['Service'])

        # Adding M2M table for field proxy on 'Service'
        m2m_table_name = db.shorten_name(u'authentic2_idp_cas_service_proxy')
        db.create_table(m2m_table_name, (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('from_service', models.ForeignKey(orm[u'authentic2_idp_cas.service'], null=False)),
            ('to_service', models.ForeignKey(orm[u'authentic2_idp_cas.service'], null=False))
        ))
        db.create_unique(m2m_table_name, ['from_service_id', 'to_service_id'])

        # Adding model 'Attribute'
        db.create_table(u'authentic2_idp_cas_attribute', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('service', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['authentic2_idp_cas.Service'])),
            ('slug', self.gf('django.db.models.fields.SlugField')(max_length=50)),
            ('attribute_name', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('enabled', self.gf('django.db.models.fields.BooleanField')(default=True)),
        ))
        db.send_create_signal(u'authentic2_idp_cas', ['Attribute'])

        # Adding unique constraint on 'Attribute', fields ['service', 'slug', 'attribute_name']
        db.create_unique(u'authentic2_idp_cas_attribute', ['service_id', 'slug', 'attribute_name'])

        # Adding model 'Ticket'
        db.create_table(u'authentic2_idp_cas_ticket', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('ticket_id', self.gf('django.db.models.fields.CharField')(default='ST-Gq6TakTkHQW5iXh66NPXwES6uA', unique=True, max_length=64)),
            ('renew', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('validity', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('service', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['authentic2_idp_cas.Service'])),
            ('service_url', self.gf('django.db.models.fields.CharField')(default='', max_length=256, blank=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(max_length=128, to=orm['auth.User'], null=True, blank=True)),
            ('creation', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('expire', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('session_key', self.gf('django.db.models.fields.CharField')(default='', max_length=64, db_index=True, blank=True)),
            ('proxies', self.gf('django.db.models.fields.TextField')(default='', blank=True)),
        ))
        db.send_create_signal(u'authentic2_idp_cas', ['Ticket'])


    def backwards(self, orm):
        # Removing unique constraint on 'Attribute', fields ['service', 'slug', 'attribute_name']
        db.delete_unique(u'authentic2_idp_cas_attribute', ['service_id', 'slug', 'attribute_name'])

        # Deleting model 'Service'
        db.delete_table(u'authentic2_idp_cas_service')

        # Removing M2M table for field proxy on 'Service'
        db.delete_table(db.shorten_name(u'authentic2_idp_cas_service_proxy'))

        # Deleting model 'Attribute'
        db.delete_table(u'authentic2_idp_cas_attribute')

        # Deleting model 'Ticket'
        db.delete_table(u'authentic2_idp_cas_ticket')


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
        u'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Group']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Permission']"}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '255'})
        },
        u'authentic2_idp_cas.attribute': {
            'Meta': {'unique_together': "(('service', 'slug', 'attribute_name'),)", 'object_name': 'Attribute'},
            'attribute_name': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'enabled': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'service': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['authentic2_idp_cas.Service']"}),
            'slug': ('django.db.models.fields.SlugField', [], {'max_length': '50'})
        },
        u'authentic2_idp_cas.service': {
            'Meta': {'object_name': 'Service'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'identifier_attribute': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'logout_url': ('django.db.models.fields.URLField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'logout_use_iframe': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'logout_use_iframe_timeout': ('django.db.models.fields.PositiveIntegerField', [], {'default': '300'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '128'}),
            'proxy': ('django.db.models.fields.related.ManyToManyField', [], {'related_name': "'proxy_rel_+'", 'to': u"orm['authentic2_idp_cas.Service']"}),
            'slug': ('django.db.models.fields.SlugField', [], {'unique': 'True', 'max_length': '128'}),
            'urls': ('django.db.models.fields.TextField', [], {'max_length': '128'})
        },
        u'authentic2_idp_cas.ticket': {
            'Meta': {'object_name': 'Ticket'},
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'expire': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'proxies': ('django.db.models.fields.TextField', [], {'default': "''", 'blank': 'True'}),
            'renew': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'service': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['authentic2_idp_cas.Service']"}),
            'service_url': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '256', 'blank': 'True'}),
            'session_key': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '64', 'db_index': 'True', 'blank': 'True'}),
            'ticket_id': ('django.db.models.fields.CharField', [], {'default': "'ST-qyRI9QrItD6Gy5YdLNHCixDRnT'", 'unique': 'True', 'max_length': '64'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'max_length': '128', 'to': u"orm['auth.User']", 'null': 'True', 'blank': 'True'}),
            'validity': ('django.db.models.fields.BooleanField', [], {'default': 'False'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        }
    }

    complete_apps = ['authentic2_idp_cas']