
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
    if hasattr(user, 'get_attribute_aggregator_attributes'):
        return {
             'simple': user.get_attribute_aggregator_attributes(),
        }
    else:
        return {}
