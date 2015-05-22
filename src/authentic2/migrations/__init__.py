import itertools
import hashlib

from django.db.migrations.operations.base import Operation

class CreatePartialIndexes(Operation):
    reversible = True

    def __init__(self, table_name, index_name, nullable_columns, non_null_columns, null_columns=()):
        self.table_name = table_name
        self.index_name = index_name
        assert not set(nullable_columns) & set(non_null_columns)
        assert not set(null_columns) & set(non_null_columns)
        assert not set(null_columns) & set(nullable_columns)
        self.nullable_columns = set(nullable_columns)
        self.non_null_columns = set(non_null_columns)
        self.null_columns = set(null_columns)

    def indexes(self):
        for i in range(0, len(self.nullable_columns)+1):
            for null_columns in itertools.combinations(sorted(self.nullable_columns), i):
                non_null_columns = self.non_null_columns | (self.nullable_columns - set(null_columns))
                null_columns = set(null_columns) | self.null_columns
                non_null_columns = sorted(non_null_columns)
                index_name = '%s_uniq_%s' % (self.table_name, '_'.join(non_null_columns))
                yield null_columns, non_null_columns

    def state_forwards(self, app_label, state):
        pass

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        for i, (null_columns, non_null_columns) in enumerate(self.indexes()):
            index = ', '.join(non_null_columns)
            if null_columns:
                where = ' AND '.join('"%s" IS NULL' % col for col in null_columns)
                schema_editor.execute('CREATE UNIQUE INDEX "%s_%s" ON %s (%s) WHERE %s' % (self.index_name, i, self.table_name, index, where))
            else:
                schema_editor.execute('CREATE UNIQUE INDEX "%s_%s" ON %s (%s)' % (self.index_name, i, self.table_name, index))

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        for i, (null_columns, non_null_columns) in enumerate(self.indexes()):
            schema_editor.execute('DROP INDEX "%s_%s"' % (self.index_name, i))

    def describe(self):
        return "Create partial indexes"
