import json
import sys

from django.utils import six
from django.core.serializers.json import Serializer as JSONSerializer
from django.core.serializers.python import _get_model
from django.core.serializers.base import DeserializationError
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import DEFAULT_DB_ALIAS


class Serializer(JSONSerializer):
    def end_object(self, obj):
        concrete_model = obj._meta.concrete_model
        for vfield in concrete_model._meta.virtual_fields:
            if not isinstance(vfield, GenericForeignKey):
                continue
            ct = getattr(obj, vfield.ct_field)
            if ct is None:
                continue
            sub_obj = getattr(obj, vfield.name)
            assert not sub_obj is None, 'should not happen'
            if not hasattr(sub_obj, 'natural_key'): 
                # abort if no natural key
                continue
            # delete non natural keys
            del self._current[vfield.ct_field]
            del self._current[vfield.fk_field]
            self._current[vfield.name] = (ct.natural_key(), sub_obj.natural_key())
        super(Serializer, self).end_object(obj)

def PreDeserializer(objects, **options):
    db = options.pop('using', DEFAULT_DB_ALIAS)

    for d in objects:
        Model = _get_model(d["model"])
        for vfield in Model._meta.virtual_fields:
            if not vfield.name in d['fields']:
                continue
            ct_natural_key, fk_natural_key = d['fields'][vfield.name]
            ct = ContentType.objects.get_by_natural_key(*ct_natural_key)
            obj = ct.model_class()._default_manager.db_manager(db).get_by_natural_key(*fk_natural_key)
            d['fields'][vfield.ct_field] = ct.pk
            d['fields'][vfield.fk_field] = obj.pk
            del d['fields'][vfield.name]
        yield d

def Deserializer(stream_or_string, **options):
    """
    Deserialize a stream or string of JSON data.
    """
    from django.core.serializers.python import Deserializer as PythonDeserializer
    if not isinstance(stream_or_string, (bytes, six.string_types)):
        stream_or_string = stream_or_string.read()
    if isinstance(stream_or_string, bytes):
        stream_or_string = stream_or_string.decode('utf-8')
    try:
        objects = json.loads(stream_or_string)
        objects = PreDeserializer(objects, **options)
        for obj in PythonDeserializer(objects, **options):
            yield obj
    except GeneratorExit:
        raise
    except Exception as e:
        # Map to deserializer error
        six.reraise(DeserializationError, DeserializationError(e), sys.exc_info()[2])
