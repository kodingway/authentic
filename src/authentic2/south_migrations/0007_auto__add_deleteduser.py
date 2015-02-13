# -*- coding: utf-8 -*-
from south.db import db
from south.v2 import SchemaMigration

from authentic2.compat import user_model_label


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'DeletedUser'
        db.create_table(u'authentic2_deleteduser', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[user_model_label])),
            ('creation', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
        ))
        db.send_create_signal(u'authentic2', ['DeletedUser'])


    def backwards(self, orm):
        # Deleting model 'DeletedUser'
        db.delete_table(u'authentic2_deleteduser')


    models = {
        u'authentic2.deleteduser': {
            'Meta': {'object_name': 'DeletedUser'},
            'creation': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" % user_model_label})
        },
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
        },
    }

    complete_apps = ['authentic2']
