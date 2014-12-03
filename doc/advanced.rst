.. _advanced:

===============
Advanced topics
===============


- :ref:`attributes_in_session`
- :ref:`writing_migrations`
- :ref:`write_new_kind_policy`

.. _attributes_in_session:

Attributes in session pushed by third SAML2 identity providers
==============================================================

When an assertion is received, assertion data, including attributes, are
pushed in the Django session dictionnary.

It leads to the creation of the following dictionnary::

    request.session['multisource_attributes']

The keys of the dictionnary are the source names, i.e. the entity Id for
SAML2 identity providers.

The values are list of data extracted from assertions. Indeed, this is done
to store multiple assertion received from a same source in a same Django
session::

    request.session['multisource_attributes'] \
        [source_name] = list()

The items of this list are dictionnaries with the keys 'certificate_type' and
'attributes'.

For a saml2 assertion, all the keys are::

    a8n['certificate_type'] = 'SAML2_assertion'
    a8n['nameid'] = ...
    a8n['subject_confirmation_method'] = ...
    a8n['not_before'] = ...
    a8n['not_on_or_after'] = ...
    a8n['authn_context'] = ...
    a8n['authn_instant'] = ...
    a8n['attributes'] = attrs

a8n['attributes'] has the following structure::

    attributes = {}
    attributes[name] = (value1, value2, )
    attributes[(name, format)] = (value1, value2, )
    attributes[(name, format, nickname)] = (value1, value2, )
    a8n['attributes'] = attributes

.. _writing_migrations:

Writing migrations
==================

Migration containing reference to the user model must be rewritten manually to
refer to the user model name indirectly. The followind modifications must be applied.

1. First import the `user_model_label` from the `authentic2.compat` module:

::

    from authentic2.compat import user_model_label

Any reference to `orm['auth.User']` or `orm['authentic2.User']` must be
rewritten into `orm[user_model_label]`. For example this line:::

    ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['authentic2.User'])),

must be changed to:::

    ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm[user_model_label])),

2. The user model when appearing in the `models` field like this:

::

        u'auth.user': {
            'meta': {'object_name': 'User',

must be rewritten like that:::

        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},

3. If the user model is referred inside the `to` field of a foreign key
   declaration like this:

::

        'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"})

   must be rewritten like that:::

        'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['%s']" user_model_label})

.. _write_new_kind_policy:

Add a new kind of administration policy
=======================================

See how policies works :ref:`administration_with_policies`. Then, the bahavior
should look like::

    def get_sample_policy(any_object):
        # Look for a global policy 'All'
        try:
            return SamplePolicy.objects.get(name='All', enabled=True)
        except SamplePolicy.DoesNotExist:
            pass
        # Look for a regular policy
        if any_object.enable_following_sample_policy:
            if any_object.sample_policy:
                return any_object.sample_policy
        # Look for a global policy 'Default'
        try:
            return SamplePolicy.objects.get(name='Default', enabled=True)
        except SamplePolicy.DoesNotExist:
            pass
        return None
