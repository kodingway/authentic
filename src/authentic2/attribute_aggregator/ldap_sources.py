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
import ldap

from authentic2.attribute_aggregator.core import get_user_alias_in_source


logger = logging.getLogger(__name__)


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
    if not user:
        logger.error('get_attributes: No user provided')
        return None
    logger.debug('get_attributes: Searching attributes')

    from authentic2.attribute_aggregator.models import LdapSource
    sources = None
    if source and not auth_source:
        logger.debug('get_attributes: The required source is %s' % source)
        try:
            sources = [source.ldapsource]
        except LdapSource.DoesNotExist:
            logger.debug('get_attributes: \
                The required source is not a LDAP one')
            return None
        else:
            logger.debug('get_attributes: The source is an LDAP source!')
    else:
        sources = LdapSource.objects.all()
    if not sources:
        logger.debug('get_attributes: No LDAP source configured')
        return None

    attributes = dict()

    for source in sources:
        logger.debug('get_attributes: The LDAP source is known as %s' \
            % source.name)
        '''
            Check if the user is authenticated by LDAP.
            If it is, grab the user dn from the LDAPUser object

            We support our LDAP backend and django_auth_ldap.
            The way to grab the dn from the session is different.

            Check also if the source we have to grab attributes from is the
            ldap used as backend. Else, the dn in session is not for that LDAP
            source.

            If we only want attributs from the authn backend, if the ldap
            source is not the used for authn, stop process.
        '''
        dn = None
        is_source_backend = False
        source_url = source.get_url()

        dn = getattr(user, 'dn', None)
        # Only a single ldap can be used as backend with django_auth_ldap
        if dn and hasattr(user, 'block'):
            for back_url in user.block.get('url'):
                if back_url == source_url:
                    is_source_backend = True
                    break
        if auth_source and not is_source_backend:
            logger.debug('get_attributes: only attributes from backend and '
                'this source is not, see next')
            continue
        if not dn:
            dn = get_user_alias_in_source(user, source)
        if not dn:
            logger.debug('get_attributes: \
                No user identifier known into that source %s' % source.name)
            continue

        logger.debug('get_attributes: \
            the user is known as %s in source %s' \
            % (dn, source.name))

        try:
            l = ldap.open(source.server, port=source.port)
            l.protocol_version = ldap.VERSION3
            username = source.user
            password = source.password
            if username and password:
                l.simple_bind(username, password)
        except ldap.LDAPError, err:
            logger.error('get_attributes: \
                an error occured at binding due to %s' % err)
        else:
            '''
                No seach of user with the scope, only exact dn
            '''
#                base_dn = source.base
#                search_scope = ldap.SCOPE_SUBTREE
            search_scope = ldap.SCOPE_BASE
            retrieve_attributes = None
            if definitions:
                #The definition name is the ldap attribute name
                logger.debug('get_attributes: attributes requested \
                    are %s' % definitions)
                retrieve_attributes = \
                    [d.encode('utf-8') for d in definitions]
#                dn = ldap.dn.explode_dn(identifier,
#                    flags=ldap.DN_FORMAT_LDAPV3)
#                search_filter = dn[0]
#                logger.debug('get_attributes: rdn is %s' % search_filter)

            data = []
            try:
#                    ldap_result_id = l.search(base_dn, search_scope,
#                        search_filter, retrieve_attributes)
                ldap_result_id = l.search(dn, search_scope,
                    attrlist=retrieve_attributes)
                result_type, result_data = l.result(ldap_result_id, 0)
                logger.debug('get_attributes: result %s %s' \
                    % (result_type, result_data))
                for d, dic in result_data:
                    logger.debug('get_attributes: found %s' % d)
                    if d == dn:
                        logger.debug('get_attributes: \
                            Attributes are %s' % dic)
                        for key in dic.keys():
                            attr = {}
                            attr['definition'] = key
                            attr['values'] = [\
                                a.decode('utf-8') for a in dic[key]]
                            data.append(attr)
            except ldap.LDAPError, err:
                logger.error('get_attributes: \
                    an error occured at searching due to %s' % err)
            else:
                if not data:
                    logger.error('get_attributes: no attribute found')
                else:
                    if auth_source:
                        attributes['AUTH_BACKEND'] = data
                    else:
                        attributes[source.name] = data

    logger.debug('get_attributes: the attributes returned are %s' \
        % attributes)
    return attributes
