# -*- coding: utf-8 -*-
from south.db import db
from south.v2 import SchemaMigration

from django.contrib.contenttypes.models import ContentType

class Migration(SchemaMigration):
    depends_on = (
            ('authentic2', '0011_auto__add_authenticationevent'),
    )

    def forwards(self, orm):
        # Deleting model 'AuthenticationEvent'
        db.delete_table('authentic2_authenticationevent')
        db.rename_table('auth2_auth_authenticationevent', 'authentic2_authenticationevent')
        db.send_create_signal('authentic2', ['AuthenticationEvent'])
        if not db.dry_run:
            ContentType.objects.filter(app_label='authentic2',
                    model='authenticationevent').delete()
            ContentType.objects.filter(app_label='auth2_auth') \
                    .update(app_label='authentic2')


    def backwards(self, orm):
        if not db.dry_run:
            ContentType.objects.filter(app_label='authentic2',
                    model='authenticationevent').update(app_label='auth2_auth')
        db.rename_table('authentic2_authenticationevent', 'auth2_auth_authenticationevent')
        db.send_create_signal('auth2_auth', ['AuthenticationEvent'])


    models = {
        
    }

    complete_apps = ['auth2_auth']
