import json
import sys

from django.utils import six
from django.core.serializers.json import Serializer as JSONSerializer
from django.core.serializers.python import Deserializer as \
    PythonDeserializer, _get_model
from django.core.serializers.base import DeserializationError

class Serializer(JSONSerializer):
    def get_dump_object(self, obj):
        d = super(Serializer, self).get_dump_object(obj)
        if self.use_natural_keys and hasattr(obj, 'natural_key'):
            d['pk'] = obj.natural_key()
        return d

def Deserializer(stream_or_string, **options):
    """
    Deserialize a stream or string of JSON data.
    """
    if not isinstance(stream_or_string, (bytes, six.string_types)):
        stream_or_string = stream_or_string.read()
    if isinstance(stream_or_string, bytes):
        stream_or_string = stream_or_string.decode('utf-8')
    try:
        objects = json.loads(stream_or_string)
        for obj in objects:
            Model = _get_model(obj['model'])
            if isinstance(obj['pk'], (tuple, list)):
                try:
                    o = Model.objects.get_by_natural_key(*obj['pk'])
                except Model.DoesNotExist:
                    obj['pk'] = None
                else:
                    obj['pk'] = o.pk
        for obj in PythonDeserializer(objects, **options):
            yield obj
    except GeneratorExit:
        raise
    except Exception as e:
        # Map to deserializer error
        six.reraise(DeserializationError, DeserializationError(e), sys.exc_info()[2])


