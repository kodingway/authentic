import itertools

import django
from django.db.migrations.operations.base import Operation


class CreatePartialIndexes(Operation):
    reversible = True

    def __init__(self, model_name, table_name, index_name, nullable_columns, non_null_columns,
                 null_columns=None, where=None):
        self.model_name = model_name
        self.table_name = table_name
        self.index_name = index_name
        null_columns = null_columns or ()
        assert not set(nullable_columns) & set(non_null_columns)
        assert not set(null_columns) & set(non_null_columns)
        assert not set(null_columns) & set(nullable_columns)
        self.nullable_columns = set(nullable_columns)
        self.non_null_columns = set(non_null_columns)
        self.where = set(where or [])
        if null_columns:
            for column in null_columns:
                self.where.add('"%s" IS NULL' % column)

    def allowed(self, app_label, schema_editor, to_state):
        if django.VERSION < (1, 8, 0):
            to_model = to_state.render().get_model(app_label, self.model_name)
            if not self.allowed_to_migrate(schema_editor.connection.alias, to_model):
                return False
        else:
            to_model = to_state.apps.get_model(app_label, self.model_name)
            if not self.allow_migrate_model(schema_editor.connection.alias, to_model):
                return False
        if schema_editor.connection.vendor == 'postgresql':
            return True
        # Partial indexed were introduced in sqlite 3.8.0
        if schema_editor.connection.vendor == 'sqlite' and \
                schema_editor.connection.Database.sqlite_version_info >= (3, 8):
            return True
        return False

    def indexes(self):
        for i in range(0, len(self.nullable_columns)+1):
            for null_columns in itertools.combinations(sorted(self.nullable_columns), i):
                non_null_columns = self.non_null_columns | (self.nullable_columns - set(null_columns))
                where = self.where.copy()
                for column in null_columns:
                    where.add('"%s" IS NULL' % column)
                non_null_columns = sorted(non_null_columns)
                yield where, non_null_columns

    def state_forwards(self, app_label, state):
        pass

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if not self.allowed(app_label, schema_editor, to_state):
            return
        for i, (where, non_null_columns) in enumerate(self.indexes()):
            index = ', '.join(non_null_columns)
            if where:
                where_clause = ' AND '.join(where)
                schema_editor.execute('CREATE UNIQUE INDEX "%s_%s" ON %s (%s) WHERE %s' %
                                      (self.index_name, i, self.table_name, index, where_clause))
            else:
                schema_editor.execute('CREATE UNIQUE INDEX "%s_%s" ON %s (%s)' % (self.index_name, i, self.table_name, index))

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if not self.allowed(app_label, schema_editor, to_state):
            return
        for i, (null_columns, non_null_columns) in enumerate(self.indexes()):
            schema_editor.execute('DROP INDEX IF EXISTS "%s_%s"' % (self.index_name, i))

    def describe(self):
        return "Create partial indexes"
