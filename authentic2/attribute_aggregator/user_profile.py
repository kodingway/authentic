'''
    Authentic 2 - Versatile Identity Server

    Copyright (C) 2011 Entr'ouvert

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''


import logging
from operator import attrgetter, __or__
import six


from authentic2.attribute_aggregator.core import (get_profile_field_name_from_definition,
    get_definitions_from_profile_field_name, is_definition, get_def_name_from_alias, get_aliases)


logger = logging.getLogger(__name__)

SOURCE_NAME = 'USER_PROFILE'

def get_attributes(user, definitions=None, source=None, auth_source=False, **kwargs):
    '''
        Return attributes dictionnary

        Dictionnary format:
        attributes = dict()
        data_from_source = list()
        a1 = dict()
                a1['oid'] = definition_name
            Or
                a1['definition'] = definition_name
                    definition may be the definition name like 'gn'
                    or an alias like 'givenName'
            Or
                a1['name'] = attribute_name_in_ns
                a1['namespace'] = ns_name
        a1['values'] = list_of_values
        data_from_source.append(a1)
        ...
        data_from_source.append(a2)
        attributes[source_name] = data_from_source

        First attempt on 'definition' key.
        Else, definition is searched by 'name' and 'namespece' keys.
    '''
    from models import AttributeSource
    try:
        AttributeSource.objects.get(name=SOURCE_NAME)
    except AttributeSource.DoesNotExist:
        logger.debug('USER_PROFILE source is inactive')
        return None
    if source and source.name != SOURCE_NAME:
        logger.debug('USER_PROFILE source ignored as source %r is required',
                source.name)
        return None

    data = {}
    if hasattr(user, 'get_attributes') and callable(user.get_attributes):
        attributes = user.get_attributes()
        if not definitions:
            definitions = []
            for key in attributes:
                if is_definition(key):
                    definitions.add(key)
                else:
                    definition = get_def_name_from_alias(key)
                    if definition:
                        definitions.add(definition)
        for definition in definitions:
            new = []
            for key in get_aliases(definition):
                if key in attributes:
                    new.append(set(attributes[key]))
            if not new:
                continue
            new = reduce(__or__, new)
            old = data.get(definition, [])
            data[definition] = list(set(old) | set(new))
    field_names = set()
    user_profile_fields = getattr(user, 'USER_PROFILE', [])
    if not user_profile_fields:
        user_profile_fields = user._meta.get_all_field_names()
    for field in user_profile_fields:
        if isinstance(field, (tuple, list)):
            field_names.add(field[0])
        else:
            field_names.add(field)
    fields = []
    if definitions:
        for definition in definitions:
            field_name = get_profile_field_name_from_definition(definition)
            if not field_name:
                #
                #  Profile model may be extended without modifying the
                #  mapping file if the attribute name is the same as the
                #  definition
                #
                field_name = definition
            fields.append((field_name, definition))
    else:
        fields = [(field_name, definition)
                    for definition in get_definitions_from_profile_field_name(field_name)
                    for field_name in field_names]
    logger.debug('retrieving fields %r from USER_PROFILE', fields)
    data = {}
    for field_name, definition in fields:
        try:
            value = attrgetter(field_name)(user)
        except AttributeError:
            logger.debug('field %r not found in USER_PROFILE', field_name)
            continue
        if value:
            if callable(value):
                value = value()
            if hasattr(value, 'all') and callable(value.all):
                value = value.all()
            logger.debug('field %r has value %r', field_name, value)
            old = data.get(definition, [])
            if not isinstance(value, six.string_types) and hasattr(value,
                    '__iter__'):
                new = map(unicode, value)
            else:
                new = [unicode(value)]
            if not old:
                data[definition] = new
        else:
            logger.debug('get_attributes: no value found')
    data = [{'definition': definition, 'values': values} for definition, values in 
            data.items()]
    return {SOURCE_NAME: data}
