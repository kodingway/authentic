# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.db import models, migrations

class ThirdPartyAlterField(migrations.AlterField):
    def __init__(self, *args, **kwargs):
        self.app_label = kwargs.pop('app_label')
        super(ThirdPartyAlterField, self).__init__(*args, **kwargs)

    def state_forwards(self, app_label, state):
        super(ThirdPartyAlterField, self).state_forwards(self.app_label, state)

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        super(ThirdPartyAlterField, self).database_forwards(self.app_label,
                schema_editor, from_state, to_state)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        self.database_forwards(app_label, schema_editor, from_state, to_state)

    def __eq__(self, other):
        return (
            (self.__class__ == other.__class__) and
            (self.app_label == other.app_label) and
            (self.name == other.name) and
            (self.model_name.lower() == other.model_name.lower()) and
            (self.field.deconstruct()[1:] == other.field.deconstruct()[1:])
        )

    def references_model(self, *args, **kwargs):
        return True

    def references_field(self, *args, **kwargs):
        return True


class Migration(migrations.Migration):
    dependencies = [
        ('custom_user', '0001_initial'),
        ('menu', '__first__'),
        ('admin', '__first__'),
    ]

    run_before = [
        ('auth', '0003_auto_20150410_1657'),
    ]

    operations = [
            # Django admin log
            ThirdPartyAlterField(
                app_label='admin',
                model_name='logentry',
                name='user',
                field=models.ForeignKey(to=settings.AUTH_USER_MODEL),
                preserve_default=True
            ),
            # Django admin-tools menu bookmark
            ThirdPartyAlterField(
                app_label='menu',
                model_name='bookmark',
                name='user',
                field=models.ForeignKey(to=settings.AUTH_USER_MODEL),
                preserve_default=True
            ),
    ]
