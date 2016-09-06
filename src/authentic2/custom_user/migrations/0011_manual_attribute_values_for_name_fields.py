# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations
from django.utils import translation
from django.utils.translation import ugettext_lazy as _

from authentic2.attribute_kinds import get_kind


def create_attribute_value_for_names(apps, schema_editor):
    translation.activate(settings.LANGUAGE_CODE)

    Attribute = apps.get_model('authentic2', 'Attribute')
    AttributeValue = apps.get_model('authentic2', 'AttributeValue')
    User = apps.get_model('custom_user', 'User')
    ContentType = apps.get_model('contenttypes', 'ContentType')

    # django.contrib.contenttypes.management.update_contenttypes cannot be used
    # as we don't have a real app_config object.  Therefore we insert an entry
    # in content type table if it didn't exist.
    content_type, created = ContentType.objects.get_or_create(
            model='user', app_label='custom_user')
    if created:
        content_type.save()

    attrs = {}
    attrs['first_name'], created = Attribute.objects.get_or_create(
        name='first_name',
        defaults={'kind': 'string',
                  'label': _('First name'),
                  'required': True,
                  'asked_on_registration': True,
                  'user_editable': True,
                  'user_visible': True})
    if created:
        attrs['first_name'].save()

    attrs['last_name'], created = Attribute.objects.get_or_create(
        name='last_name',
        defaults={'kind': 'string',
                  'label': _('Last name'),
                  'required': True,
                  'asked_on_registration': True,
                  'user_editable': True,
                  'user_visible': True})

    if created:
        attrs['last_name'].save()

    serialize = get_kind('string').get('serialize')
    for user in User.objects.all():
        for attr_name in ('first_name', 'last_name'):
            av, created = AttributeValue.objects.get_or_create(
                content_type=content_type,
                object_id=user.id,
                attribute=attrs[attr_name],
                multiple=False,
                verified=False,
                content=serialize(getattr(user, attr_name, None)))
            if created:
                av.save()


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '__first__'),
        ('custom_user', '0010_auto_20160307_1418'),
        ('authentic2', '0015_auto_20160621_1711'),
    ]

    operations = [
        migrations.RunPython(create_attribute_value_for_names, lambda *x: None),
    ]
