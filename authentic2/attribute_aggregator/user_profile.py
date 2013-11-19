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

from django.contrib.auth.models import SiteProfileNotAvailable
from django.core.exceptions import ObjectDoesNotExist

from authentic2.attribute_aggregator.core import get_profile_field_name_from_definition, \
    get_definitions_from_profile_field_name


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
    except:
        logger.debug('get_attributes: \
            Profile source not configured')
        return None
    if source and source.name != SOURCE_NAME:
        logger.debug('get_attributes: '
                'The required source %s is not user profile' % source)
        return None

    attributes = dict()
    data = []
    try:
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
                logger.debug('get_attributes: looking for %s' % definition)
                field_name = get_profile_field_name_from_definition(definition)
                if not field_name:
                    '''
                        Profile model may be extended without modifying the
                        mapping file if the attribute name is the same as the
                        definition
                    '''
                    logger.debug('get_attributes: '
                            'Field name will be the definition')
                    field_name = definition
                if field_name in field_names:
                    fields.append((field_name, definition))
                else:
                    logger.debug('get_attributes: Field not found in profile')
        else:
            fields = [(field_name, definition)
                        for definition in get_definitions_from_profile_field_name(field_name)
                        for field_name in field_names]
        for field_name, definition in fields:
            logger.debug('get_attributes: found field %s' % (field_name,))
            value = getattr(user, field_name, None)
            if value:
                if callable(value):
                    value = value()
                logger.debug('get_attributes: found value %s' % value)
                attr = {}
                attr['definition'] = definition
                if not isinstance(value, basestring) and hasattr(value,
                        '__iter__'):
                    attr['values'] = map(unicode, value)
                else:
                    attr['values'] = [unicode(value)]
                data.append(attr)
            else:
                logger.debug('get_attributes: no value found')
    except (SiteProfileNotAvailable, ObjectDoesNotExist):
        logger.debug('get_attributes: No user profile')
        return None
    attributes[SOURCE_NAME] = data
    return attributes
