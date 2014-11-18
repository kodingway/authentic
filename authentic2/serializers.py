import json
import sys

from django.utils import six
from django.core.serializers.json import Serializer as JSONSerializer
from django.core.serializers.python import _get_model
from django.core.serializers import base
from django.core.serializers.base import DeserializationError
from django.contrib.contenttypes.generic import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db.models import FieldDoesNotExist
from django.utils.encoding import smart_text
from django.conf import settings
from django.db import models, DEFAULT_DB_ALIAS


def PythonDeserializer(object_list, **options):
    """
    Deserialize simple Python objects back into Django ORM instances.

    It's expected that you pass the Python objects themselves (instead of a
    stream or a string) to the constructor
    """
    db = options.pop('using', DEFAULT_DB_ALIAS)
    ignore = options.pop('ignorenonexistent', False)

    for d in object_list:
        # Look up the model and starting build a dict of data for it.
        Model = _get_model(d["model"])
        data = {}
        if 'pk' in d:
            data[Model._meta.pk.attname] = Model._meta.pk.to_python(d.get("pk", None))
        m2m_data = {}
        model_fields = Model._meta.get_all_field_names()

        # Handle each field
        for (field_name, field_value) in six.iteritems(d["fields"]):

            if ignore and field_name not in model_fields:
                # skip fields no longer on model
                continue

            if isinstance(field_value, str):
                field_value = smart_text(field_value, options.get("encoding", settings.DEFAULT_CHARSET), strings_only=True)

            try:
                field = Model._meta.get_field(field_name)
            except FieldDoesNotExist:
                for field in Model._meta.virtual_fields:
                    if field.name == field_name:
                        break
                else:
                    raise


            # Handle M2M relations
            if hasattr(field, 'rel'):
                if field.rel and isinstance(field.rel, models.ManyToManyRel):
                    if hasattr(field.rel.to._default_manager, 'get_by_natural_key'):
                        def m2m_convert(value):
                            if hasattr(value, '__iter__') and not isinstance(value, six.text_type):
                                return field.rel.to._default_manager.db_manager(db).get_by_natural_key(*value).pk
                            else:
                                return smart_text(field.rel.to._meta.pk.to_python(value))
                    else:
                        m2m_convert = lambda v: smart_text(field.rel.to._meta.pk.to_python(v))
                    m2m_data[field.name] = [m2m_convert(pk) for pk in field_value]

                # Handle FK fields
                elif field.rel and isinstance(field.rel, models.ManyToOneRel):
                    if field_value is not None:
                        if hasattr(field.rel.to._default_manager, 'get_by_natural_key'):
                            if hasattr(field_value, '__iter__') and not isinstance(field_value, six.text_type):
                                obj = field.rel.to._default_manager.db_manager(db).get_by_natural_key(*field_value)
                                value = getattr(obj, field.rel.field_name)
                                # If this is a natural foreign key to an object that
                                # has a FK/O2O as the foreign key, use the FK value
                                if field.rel.to._meta.pk.rel:
                                    value = value.pk
                            else:
                                value = field.rel.to._meta.get_field(field.rel.field_name).to_python(field_value)
                            data[field.attname] = value
                        else:
                            data[field.attname] = field.rel.to._meta.get_field(field.rel.field_name).to_python(field_value)
                    else:
                        data[field.attname] = None
                else:
                    data[field.name] = field.to_python(field_value)
            # Handle Generic foreign key
            elif isinstance(field, GenericForeignKey):
                ct_natural_key, fk_natural_key = field_value
                ct = ContentType.objects.get_by_natural_key(*ct_natural_key)
                data[field.name] = ct.model_class().objects.get_by_natural_key(*fk_natural_key)
            # Handle all other fields
            else:
                raise NotImplementedError('unsupported field type %s' % field)

        yield base.DeserializedObject(Model(**data), m2m_data)
    

class Serializer(JSONSerializer):
    def get_dump_object(self, obj):
        d = super(Serializer, self).get_dump_object(obj)
        if self.use_natural_keys:
            if hasattr(obj, 'natural_key'):
                d['pk'] = obj.natural_key()
            for vfield in obj.__class__._meta.virtual_fields:
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
                fields = d['fields']
                del fields[vfield.ct_field]
                del fields[vfield.fk_field]
                fields[vfield.name] = (ct.natural_key(), sub_obj.natural_key())
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
        def handle_natural_keys():
            for obj in objects:
                Model = _get_model(obj['model'])
                if isinstance(obj['pk'], (tuple, list)):
                    try:
                        o = Model.objects.get_by_natural_key(*obj['pk'])
                    except Model.DoesNotExist:
                        obj['pk'] = None
                    else:
                        obj['pk'] = o.pk
                yield obj
        for obj in PythonDeserializer(handle_natural_keys(), **options):
            yield obj
    except GeneratorExit:
        raise
    except Exception as e:
        # Map to deserializer error
        six.reraise(DeserializationError, DeserializationError(e), sys.exc_info()[2])


