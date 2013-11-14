# -*- coding: utf-8 -*-
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


import datetime
import logging

from cPickle import loads, dumps
import lasso

from django.utils.translation import ugettext_lazy as _
from django.db import models
from django.conf import settings
try:
    import ldap
except ImportError:
    ldap = None

from .mapping_loader import ATTRIBUTE_MAPPING, ATTRIBUTE_NAMESPACES
from .core import (convert_from_string,
    get_def_name_from_name_and_ns_of_attribute, iso8601_to_datetime,
    get_def_name_from_oid, get_def_name_from_alias,
    is_alias_of_definition, is_oid_of_definition)


logger = logging.getLogger(__name__)

ATTRIBUTES = [(key, key) \
    for key in sorted(ATTRIBUTE_MAPPING.iterkeys())]

ATTRIBUTES_NS = [('Default', 'Default')] \
    + [(ns, ns) for ns in ATTRIBUTE_NAMESPACES]

ATTRIBUTE_VALUE_FORMATS = (
        (lasso.SAML2_ATTRIBUTE_NAME_FORMAT_URI, 'SAMLv2 URI'),
        (lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC, 'SAMLv2 BASIC'))


class AttributeItem(models.Model):
    attribute_name = models.CharField(
        verbose_name = _("Attribute name"),
        max_length = 100, choices = ATTRIBUTES,
        default = ATTRIBUTES[0])
    # ATTRIBUTE_VALUE_FORMATS[0] =>
    #    (lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC, 'SAMLv2 BASIC')
    output_name_format = models.CharField(
        verbose_name = _("Output name format"),
        max_length = 100,
        choices = ATTRIBUTE_VALUE_FORMATS,
        default = ATTRIBUTE_VALUE_FORMATS[0])
    #ATTRIBUTES_NS[0] => ('Default', 'Default')
    output_namespace = models.CharField(
        verbose_name = _("Output namespace"),
        max_length = 100,
        choices = ATTRIBUTES_NS, default = ATTRIBUTES_NS[0])
    required = models.BooleanField(
        verbose_name = _("Required"),
        default=False)
    source = models.ForeignKey('attribute_aggregator.AttributeSource',
        verbose_name = _("Attribute source"),
        blank = True, null = True)

    class Meta:
        verbose_name = _('attribute list item')
        verbose_name_plural = _('attribute list items')

    def __unicode__(self):
        s = self.attribute_name
        attributes = []
        attributes.append(u'output name fomat: %s' % self.output_name_format)
        attributes.append(u'output namespace: %s' % self.output_namespace)
        if self.required:
            attributes.append(u'required')
        if self.source:
            attributes.append(u'source: %s' % self.source)
        s += u' (%s)' % u', '.join(attributes)
        return s

    def __repr__(self):
        return '<AttributeItem {0!r}>'.format(
                self.__dict__)


class AttributeList(models.Model):
    name = models.CharField(
        verbose_name = _("Name"),
        max_length = 100, unique = True)
    attributes = models.ManyToManyField(AttributeItem,
        verbose_name = _("Attributes"),
        related_name = "attributes of the list",
        blank = True, null = True)

    class Meta:
        verbose_name = _('attribute list')
        verbose_name_plural = _('attribute lists')

    def __unicode__(self):
        return self.name

    def __repr__(self):
        return '<AttributeList name:{0!r} attributes:[{1:r}]>'.format(
                self.name, ', '.join(map(repr, self.attributes.all())))



class AttributeSource(models.Model):
    name = models.CharField(
        verbose_name = _("Name"),
        max_length = 200, unique=True)
    namespace = models.CharField(
        verbose_name = _("Namespace"),
        max_length = 100,
        choices = ATTRIBUTES_NS, default = ATTRIBUTES_NS[0])

    def __unicode__(self):
        return self.name

    def get_source_instance(self):
        try:
            return self.ldapsource
        except:
            pass
        return None

    class Meta:
        verbose_name = _('attribute source')
        verbose_name_plural = _('attribute sources')


def get_source_from_name(name):
    try:
        return AttributeSource.objects.get(name=name)
    except:
        return None


def get_all_sources():
    try:
        return AttributeSource.objects.all()
    except:
        return None

if ldap:
    class LdapSource(AttributeSource):
        server = models.CharField(
            verbose_name = _("Server"),
            max_length=200, unique=True)
        user = models.CharField(
            verbose_name = _("User"),
            max_length=200, blank=True, null=True)
        password = models.CharField(
            verbose_name = _("Password"),
            max_length=200, blank=True, null=True)
        base = models.CharField(
            verbose_name = _("Base"),
            max_length=200)
        port = models.IntegerField(
            verbose_name = _("Port"),
            default=389)
        ldaps = models.BooleanField(
            verbose_name = _("LDAPS"),
            default=False)
        certificate = models.TextField(
            verbose_name = _("Certificate"),
            blank=True)
        is_auth_backend = models.BooleanField(
            verbose_name = _("Is it used for authentication?"),
            default=False)

        def __init__(self, *args, **kwargs):
            super(LdapSource, self).__init__(*args, **kwargs)
            self.namespace = "X500"

        def get_url(self):
            port = ''
            if not (self.port == 389 or (self.port == 636 and self.ldaps)):
                port = ':%s' % str(self.port)
            return "ldap%s://%s%s" % (self.ldaps and 's' or '',
                self.server, port)

        class Meta:
            verbose_name = _('ldap attribute source')
            verbose_name_plural = _('ldap attribute sources')


class UserAliasInSource(models.Model):
    name = models.CharField(
        verbose_name = _("Name"),
        max_length = 200)
    source = models.ForeignKey(AttributeSource,
        verbose_name = _('attribute source'))
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
        verbose_name = _("user"),
        related_name='user_alias_in_source')

    class Meta:
        verbose_name = _('user alias from source')
        verbose_name_plural = _('user aliases from source')
        unique_together = ("name", "source")

    def __unicode__(self):
        return u"alias %s of user %s in %s" % (self.name, self.user,
            self.source)


class AttributeData:
    def __init__(self, definition, values=None, source=None,
            expiration_date=None):
        '''
            definition can be given by its name, an alias or an oid
        '''
        self.definition = None
        if definition in ATTRIBUTE_MAPPING:
            self.definition = definition
        else:
            d = get_def_name_from_oid(definition)
            if d:
                self.definition = d
            else:
                self.definition = get_def_name_from_alias(definition)
        if not self.definition:
            raise Exception('Definition not found.')
        self.values = list()
        if values:
            for value in values:
                if convert_from_string(self.definition, value):
                    self.values.append(value.encode('utf-8'))
        if isinstance(source, AttributeSource):
            self.source_id = source.id
        else:
            self.source_id = -1
        '''ISO8601'''
        try:
            iso8601_to_datetime(expiration_date)
            self.expiration_date = expiration_date
        except:
            self.expiration_date = None

    def get_definition(self):
        return self.definition

    def get_full_definition(self):
        if not self.definition in ATTRIBUTE_MAPPING:
            return None
        return ATTRIBUTE_MAPPING[self.definition]

    def get_exptime_in_iso8601(self):
        return self.expiration_date

    def get_exptime_in_datetime(self):
        return iso8601_to_datetime(self.expiration_date)

    def set_exptime_in_iso8601(self, expiration_date):
        try:
            iso8601_to_datetime(expiration_date)
            self.expiration_date = expiration_date
        except:
            self.expiration_date = None
        self.save()
        return self.expiration_date

    def set_exptime_in_datetime(self, expiration_date):
        try:
            self.expiration_date = expiration_date.isoformat()
        except:
            self.expiration_date = None
        self.save()
        return self.expiration_date

    def get_values(self):
        if self.values:
            return [value.decode('utf-8') for value in self.values]
        return list()

    def get_converted_values(self):
        return [convert_from_string(self.definition, value) \
            for value in self.values]

    def get_source(self):
        try:
            return AttributeSource.objects.get(pk=self.source_id)
        except:
            return None

    def get_source_id(self):
        return self.source_id

    def add_value(self, value):
        if value and convert_from_string(self.definition, value):
            try:
                self.values.append(value.encode('utf-8'))
                self.save()
                return 0
            except:
                return -1
        return -1

    def remove_value(self, value):
        if value:
            try:
                self.values.remove(value.encode('utf-8'))
                self.save()
                return 0
            except:
                return -1
        return -1

    def does_expire(self):
        if self.expiration_date:
            return self.expiration_date
        else:
            return 0

    def to_dic(self):
        '''
            a1 = dict()
                a1['oid'] = definition_name
            Or
                a1['definition'] = definition_name
                    definition may be the definition name like 'gn'
                    or an alias like 'givenName'
            a1['values'] = list_of_values
        '''
        attribute = dict()
        attribute['definition'] = self.get_definition()
        definition = self.get_full_definition()
        if 'oid' in definition:
            attribute['oid'] = definition['oid']
        attribute['values'] = self.get_values()
        return attribute

    def __unicode__(self):
        s = u"AttributeData"
        values = self.get_values()
        if values:
            s += u" %s with values %s" % (self.get_definition(), values)
        source = self.get_source()
        if source:
            s += u" from %s" % str(source)
        if self.does_expire():
            s += u" (Expires on %s)" % self.does_expire()
        return s


class UserAttributeProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, null=True,
            blank=True, related_name='user_attribute_profile')
    data = models.TextField(null=True, blank=True)

    def add_data(self, data):
        if not isinstance(data, AttributeData):
            return -1
        try:
            l = None
            if not self.data:
                l = list()
            else:
                l = loads(str(self.data))
            l.append(data)
            self.data = dumps(l)
        except:
            return -1
        self.save()
        return 0

    def remove_data(self, position):
        try:
            l = loads(str(self.data))
            res = l.pop(position)
            self.data = dumps(l)
            return res
        except:
            return None

    def get_all_data(self):
        try:
            l = loads(str(self.data))
            return l
        except:
            return []

    def get_all_data_to_dic(self):
        '''
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
        '''
        all_data = self.get_all_data()
        all_data_to_dic = dict()
        if all_data:
            for data in all_data:
                all_data_to_dic.setdefault(data.get_source().name,
                    []).append(data.to_dic())
        return all_data_to_dic

    def get_data_of_definition(self, definition, in_list=None):
        '''
            definition can be given by its name, an alias or an oid
        '''
        l = None
        if in_list:
            l = in_list
        else:
            l = self.get_all_data()
        if not l:
            return []
        return [d for d in l if d.get_definition() == definition \
            or is_alias_of_definition(d.get_definition(), definition) \
            or is_oid_of_definition(d.get_definition(), definition)]

    def get_freshest_data_of_definition(self, definition):
        l = self.get_data_of_definition(definition)
        if not l:
            return []
        l.sort(key=lambda x: x.expiration_date, reverse=True)
        return l[0]

    def get_data_of_source(self, source, in_list=None):
        l = []
        if in_list:
            l = in_list
        else:
            l = self.get_all_data()
        if not l or not isinstance(source, AttributeSource):
            return []
        return [d for d in l if d.get_source_id() == source.id]

    def get_data_of_source_by_name(self, source):
        l = self.get_all_data()
        if not l:
            return []
        s = []
        try:
            s = AttributeSource.objects.get(name=source)
        except:
            return []
        return [d for d in l if d.get_source_id() == s.id]

    def get_data_of_definition_and_source(self, definition, source):
        in_list = self.get_data_of_source(source)
        if not in_list:
            return []
        return self.get_data_of_definition(definition, in_list=in_list)

    def get_data_of_definition_and_source_by_name(self, definition, source):
        return self.get_data_of_definition(definition,
            in_list=self.get_data_of_source_by_name(source))

    def load_by_dic(self, dictionnary):
        '''
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
        if not dictionnary:
            logger.info('load_by_dic: empty dictionnary provided')
            return -1
        for source_name in dictionnary:
            logger.debug('load_by_dic: loading from source with name: %s' \
                % source_name)
            source = get_source_from_name(source_name)
            if source:
                logger.debug('load_by_dic: attributes: %s' \
                    % str(dictionnary[source_name]))
                for attribute in dictionnary[source_name]:
                    if (not 'oid' in attribute \
                            and not 'definition' in attribute \
                            and not('name' in attribute \
                                and 'namespace' in attribute)) \
                            or not 'values' in attribute:
                        logger.warn('load_by_dic: \
                            missing data to treat %s' % str(attribute))
                    else:
                        definition = None
                        if 'oid' in attribute:
                            definition = \
                                get_def_name_from_oid(attribute['oid'])
                        elif 'definition' in attribute:
                            if attribute['definition'] in ATTRIBUTE_MAPPING:
                                definition = attribute['definition']
                            else:
                                definition = \
                            get_def_name_from_alias(attribute['definition'])
                        else:
                            definition = \
                                get_def_name_from_name_and_ns_of_attribute(\
                                    attribute['name'],
                                    attribute['namespace'])
                        if not definition:
                            logger.warn('load_by_dic: \
                                unable to find definition for %s' \
                                % str(attribute))
                        else:
                            logger.debug('load_by_dic: \
                                definition %s found' % definition)

                            expiration_date = None
                            if 'expiration_date' in attribute:
                                logger.debug('load_by_dic: expire at %s' \
                                    % attribute['expiration_date'])
                                try:
                                    iso8601_to_datetime(\
                                        attribute['expiration_date'])
                                    expiration_date = \
                                        attribute['expiration_date']
                                    logger.debug('load_by_dic: expiration \
                                        date has the ISO8601 format')
                                except:
                                    logger.warn('load_by_dic: expiration \
                                        date has not the ISO8601 format')
                            if not expiration_date:
                                expiration_date = \
                                    datetime.datetime.now().isoformat()

                            values = [value for value in attribute['values'] \
                                if convert_from_string(definition, value)]

                            if self.add_data(AttributeData(\
                                    definition,
                                    values=values,
                                    source=source,
                                    expiration_date=expiration_date)) == 0:
                                logger.debug('load_by_dic: \
                                    attribute successfully added')
                            else:
                                logger.warn('load_by_dic: \
                                    error addind attribute')
            else:
                logger.critical('load_by_dic: \
                    The source with name %s providing attributes %s \
                    is unknown of the system' \
                        % (str(source_name), str(dictionnary[source_name])))
        return 0

    def load_greedy(self):
        if self.user:
            attributes_provided = any_attributes_call.send(sender=None,
                    user=self.user)
            for attrs in attributes_provided:
                logger.info('load_greedy: \
                    attributes_call connected to function %s' % \
                    attrs[0].__name__)
                if attrs[1]:
                    logger.info('load_greedy: \
                        attributes provided are %s' %str(attrs[1]))
                    self.load_by_dic(attrs[1])
                else:
                    logger.info('load_greedy: no attributes provided')

    def load_listed_attributes(self, definitions):
        '''
            definitions can be given by its name, an alias or an oid
        '''
        if self.user:
            defs = []
            for d in definitions:
                if d in ATTRIBUTE_MAPPING:
                    defs.append(d)
                else:
                    df = get_def_name_from_oid(d)
                    if df:
                        defs.append(df)
                    else:
                        df = get_def_name_from_alias(d)
                        if df:
                            defs.append(df)
            if defs:
                logger.info('load_listed_attributes: \
                    attributes required are %s' % defs)
                attributes_provided = listed_attributes_call.send(sender=None,
                        user=self.user, definitions=defs)
                for attrs in attributes_provided:
                    logger.info('load_listed_attributes: \
                        attributes_call connected to function %s' % \
                        attrs[0].__name__)
                    if attrs[1]:
                        logger.info('load_listed_attributes: \
                            attributes provided are %s' %str(attrs[1]))
                        self.load_by_dic(attrs[1])
                    else:
                        logger.info('load_listed_attributes: \
                            no attributes provided')
            else:
                logger.info('load_listed_attributes: no definitions \
                    of attributes to load with %s' % str(definitions))

    def load_listed_attributes_with_source(self, definitions, source, auth_source=False):
        if not source:
            return
        if self.user:
            defs = []
            for d in definitions:
                if d in ATTRIBUTE_MAPPING:
                    defs.append(d)
                else:
                    df = get_def_name_from_oid(d)
                    if df:
                        defs.append(df)
                    else:
                        df = get_def_name_from_alias(d)
                        if df:
                            defs.append(df)
            if defs:
                logger.info('load_listed_attributes_with_source: \
                    attributes required are %s from %s' % (defs, source))
                attributes_provided = \
                    listed_attributes_with_source_call.send(sender=None,
                        user=self.user, definitions=defs, source=source, auth_source=auth_source)
                for attrs in attributes_provided:
                    logger.info('load_listed_attributes_with_source: \
                        attributes_call connected to function %s' % \
                        attrs[0].__name__)
                    if attrs[1]:
                        logger.info('load_listed_attributes_with_source: \
                            attributes provided are %s' %str(attrs[1]))
                        self.load_by_dic(attrs[1])
                    else:
                        logger.info('load_listed_attributes_with_source: \
                            no attributes provided')
            else:
                logger.info('load_listed_attributes: no definitions \
                    of attributes to load with %s' % str(definitions))

    def process(self, context=None):
        all_data = self.get_all_data_to_dic()
        connecteds = \
            add_attributes.send(sender=self.__class__, instance=self,
                user=self.user, attributes=all_data, context=context)
        logger.info('process_with_scripts: '
            'signal add_attributes sent')
        for connected in connecteds:
            logger.info('process_with_scripts: add_attributes '
                'connected to function %s' % connected[0].__name__)
            if connected[1]:
                logger.info('process_with_scripts: attributes provided are '
                    '%s' % str(connected[1]))
                self.load_by_dic({'PROCESSING': connected[1]})

    def cleanup(self):
        l = self.get_all_data()
        if not l:
            return 0
        now = datetime.datetime.now()
        self.data = dumps([d for d in l if d.expiration_date \
            and d.get_exptime_in_datetime() > now])
        self.save()

    def __unicode__(self):
        s = u""
        if self.user:
            s = u"Profile of %s" % self.user
        else:
            s = u"Anonymous profile"
        if not self.get_all_data():
            s += u" is empty."
            return s
        s += u" that contains:"
        for d in self.get_all_data():
            s = s + u"\n\t" + d.__unicode__()
        return s

    class Meta:
        verbose_name = _('user attribute profile')
        verbose_name_plural = _('user attribute profiles')

from authentic2.attribute_aggregator.signals import any_attributes_call, \
    listed_attributes_call, listed_attributes_with_source_call, add_attributes
