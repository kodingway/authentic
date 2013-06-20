# encoding: utf-8
from south.db import db
from south.v2 import SchemaMigration


from authentic.compat import user_model_label


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'OATHTOTPSecret'
        db.create_table('auth2_oath_oathtotpsecret', (
            ('user', self.gf('django.db.models.fields.related.OneToOneField')(related_name='oath_totp_secret', unique=True, primary_key=True, to=orm[user_model_label])),
            ('key', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('drift', self.gf('django.db.models.fields.IntegerField')(default=0, max_length=4)),
        ))
        db.send_create_signal('auth2_oath', ['OATHTOTPSecret'])


    def backwards(self, orm):
        # Deleting model 'OATHTOTPSecret'
        db.delete_table('auth2_oath_oathtotpsecret')


    models = {
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
        },
        'auth2_oath.oathtotpsecret': {
            'Meta': {'object_name': 'OATHTOTPSecret'},
            'drift': ('django.db.models.fields.IntegerField', [], {'default': '0', 'max_length': '4'}),
            'key': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'oath_totp_secret'", 'unique': 'True', 'primary_key': 'True', 'to': "orm['%s']" % user_model_label})
        },
    }

    complete_apps = ['auth2_oath']
