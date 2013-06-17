Writing migrations
==================

Migration containing reference to the user model must be rewritten manually to
refer to the user model name indirectly. The followind modifications must be applied.

1. First import the `user_model_label` from the `authentic2.compat` module:::

    from authentic2.compat import user_model_label

Any reference to `orm['auth.User']` or `orm['authentic2.User']` must be
rewritten into `orm[user_model_label]`. For example this line:::

    ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['authentic2.User'])),

must be changed to:::

    ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[user_model_label])),

2. The user model when appearing in the `models` field like this:::

        u'auth.user': {
            'meta': {'object_name': 'User',

must be rewritten like that:::

        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},

3. If the user model is referred inside the `to` field of a foreign key
   declaration like this:::

        'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"})

   must be rewritten like that:::

        'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" user_model_label})
