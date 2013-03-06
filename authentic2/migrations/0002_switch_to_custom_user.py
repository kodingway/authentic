# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        db.rename_table('auth_user', 'authentic2_user')

    def backwards(self, orm):
        db.rename_table('authentc2_user', 'auth_user')

    models = {
        
    }

    complete_apps = ['authentic2']
