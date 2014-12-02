import xml.etree.ElementTree as etree
import collections
from authentic2.compat import lasso
import x509utils
import base64
import binascii
import re
import datetime
import time


def filter_attribute_private_key(message):
    return re.sub(r' (\w+:)?(PrivateKey=")([&#;\w/ +-=])+(")', '', message)

def filter_element_private_key(message):
    return re.sub(r'(<saml)(p)?(:PrivateKeyFile>-----BEGIN RSA PRIVATE KEY-----)'
        '([&#;\w/+=\s])+'
        '(-----END RSA PRIVATE KEY-----</saml)(p)?(:PrivateKeyFile>)',
        '', message)

def bool2xs(boolean):
    '''Convert a boolean value to XSchema boolean representation'''
    if boolean is True:
        return 'true'
    if boolean is False:
        return 'false'
    raise TypeError()

def int_to_b64(i):
    h = hex(i)[2:].strip('L')
    if len(h) % 2 == 1:
        h = '0' + h
    return base64.b64encode(binascii.unhexlify(h))

def keyinfo(tb, key):
    tb.pushNamespace(lasso.DS_HREF)
    tb.start('KeyInfo', {})
    if 'CERTIF' in key:
        naked = x509utils.decapsulate_pem_file(key)
        tb.start('X509Data', {})
        tb.start('X509Certificate', {})
        tb.data(naked)
        tb.end('X509Certificate')
        tb.end('X509Data')
    else:
        tb.start('KeyValue', {})
        tb.start('RSAKeyValue', {})
        tb.start('Modulus', {})
        tb.data(int_to_b64(x509utils.get_rsa_public_key_modulus(key)))
        tb.end('Modulus')
        tb.start('Exponent', {})
        tb.data(int_to_b64(x509utils.get_rsa_public_key_exponent(key)))
        tb.end('Exponent')
        tb.end('RSAKeyValue')
        tb.end('KeyValue')
    tb.end('KeyInfo')
    tb.popNamespace()

class NamespacedTreeBuilder(etree.TreeBuilder):
    def __init__(self, *args, **kwargs):
        self.__old_ns = []
        self.__ns = None
        self.__opened = []
        return etree.TreeBuilder.__init__(self, *args, **kwargs)

    def pushNamespace(self, ns):
        self.__old_ns.append(self.__ns)
        self.__ns = ns

    def popNamespace(self):
        self.__ns = self.__old_ns.pop()

    def start(self, tag, attrib):
        tag = '{%s}%s' % (self.__ns, tag)
        self.__opened.append(tag)
        return etree.TreeBuilder.start(self, tag, attrib)

    def simple_content(self, tag, data):
        self.start(tag, {})
        self.data(data)
        self.end()

    def end(self, tag = None):
        if tag:
            self.__opened.pop()
            tag = '{%s}%s' % (self.__ns, tag)
        else:
            tag = self.__opened.pop()
        return etree.TreeBuilder.end(self, tag)

class Saml2Metadata(object):
    ENTITY_DESCRIPTOR = 'EntityDescriptor'
    SP_SSO_DESCRIPTOR = 'SPSSODescriptor'
    IDP_SSO_DESCRIPTOR = 'IDPSSODescriptor'
    ARTIFACT_RESOLUTION_SERVICE = 'ArtifactResolutionService'
    SINGLE_LOGOUT_SERVICE = 'SingleLogoutService'
    MANAGE_NAME_ID_SERVICE = 'ManageNameIDService'
    SINGLE_SIGN_ON_SERVICE = 'SingleSignOnService'
    NAME_ID_MAPPING_SERVICE = 'NameIDMappingService'
    ASSERTION_ID_REQUEST_SERVICE = 'AssertionIDRequestService'
    ASSERTION_CONSUMER_SERVICE = 'AssertionConsumerService'
    PROTOCOL_SUPPORT_ENUMERATION = 'protocolSupportEnumeration'
    KEY_DESCRIPTOR = 'KeyDescriptor'
    EXTENSIONS = 'Extensions'
    DISCOVERY_RESPONSE = 'DiscoveryResponse'
    DISCOVERY_NS = 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol'
    DISCOVERY_BINDING = 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol'

    sso_services = ( ARTIFACT_RESOLUTION_SERVICE, SINGLE_LOGOUT_SERVICE,
            MANAGE_NAME_ID_SERVICE )
    idp_services = ( SINGLE_SIGN_ON_SERVICE, NAME_ID_MAPPING_SERVICE,
            ASSERTION_ID_REQUEST_SERVICE )
    sp_services = ( ASSERTION_CONSUMER_SERVICE, )
    indexed_endpoints = ( ARTIFACT_RESOLUTION_SERVICE,
            ASSERTION_CONSUMER_SERVICE )

    def __init__(self, entity_id, url_prefix = '', valid_until = None,
            cache_duration = None):
        '''Initialize a new generator for a metadata file.

           Entity id is the name of the provider
        '''
        self.entity_id = entity_id
        self.url_prefix = url_prefix
        self.role_descriptors = {}
        self.valid_until = valid_until
        self.cache_duration = cache_duration
        self.tb = NamespacedTreeBuilder()
        self.tb.pushNamespace(lasso.SAML2_METADATA_HREF)

    def add_role_descriptor(self, role, map, options):
        '''Add a role descriptor, map is a sequence of tuples formatted as

              (endpoint_type, (bindings, ..) , url [, return_url])

           endpoint_type is a string among:

              - SingleSignOnService
              - AssertionConsumer
              - SingleLogoutService
              - ManageNameIDService
              - AuthzService
              - AuthnQueryService
              - AttributeService
              - AssertionIDRequestService'''
        self.role_descriptors[role] = (map, options)

    def add_sp_descriptor(self, map, options):
        for row in map:
            if row[0] not in self.sp_services + self.sso_services:
                raise TypeError()
        self.add_role_descriptor('sp', map, options)

    def add_idp_descriptor(self, map, options):
        for row in map:
            if row[0] not in self.idp_services + self.sso_services:
                raise TypeError()
        self.add_role_descriptor('idp', map, options)

    def generate_services(self, map, options, listing):
        if options:
            if 'NameIDFormat' in options:
                for name_id_format in options['NameIDFormat']:
                    self.tb.start('NameIDFormat', {})
                    self.tb.data(name_id_format)
                    self.tb.end('NameIDFormat')
            if 'signing_key' in options:
                self.add_keyinfo(options['signing_key'], 'signing')
            if 'encryption_key' in options:
                self.add_keyinfo(options['encryption_key'], 'encryption')
            if 'key' in options:
                self.add_keyinfo(options['key'], None)
            if 'disco' in options:
                self.add_disco_extension(options['disco'])
        endpoint_idx = collections.defaultdict(lambda:0)
        for service in listing:
            selected = [ row for row in map if row[0] == service ]
            for row in selected:
                if isinstance(row[1], str):
                    bindings = [ row[1] ]
                else:
                    bindings = row[1]
                for binding in bindings:
                    attribs = { 'Binding' : binding,
                            'Location': self.url_prefix + row[2] }
                    if len(row) == 4:
                        attribs['ResponseLocation'] = self.url_prefix + row[3]
                    if service in self.indexed_endpoints:
                        if len(row) == 5:
                            if row[4] is True:
                                attribs['isDefault'] = 'true'
                            if row[4] is False:
                                attribs['isDefault'] = 'false'
                        attribs['index'] = str(endpoint_idx[service])
                        endpoint_idx[service] += 1
                    self.tb.start(service, attribs)
                    self.tb.end(service)

    def add_keyinfo(self, key, use):
        attrib = {}
        if use:
            attrib = { 'use': use }
        self.tb.start(self.KEY_DESCRIPTOR, attrib)
        keyinfo(self.tb, key)
        self.tb.end(self.KEY_DESCRIPTOR)

    def root_element(self):
        attrib = { 'entityID' : self.entity_id}
        if self.cache_duration:
            attrib['cacheDuration'] = self.cache_duration
        if self.valid_until:
            attrib['validUntil'] = self.valid_until

        self.entity_descriptor = self.tb.start(self.ENTITY_DESCRIPTOR, attrib)
        # Generate sso descriptor
        attrib =  { self.PROTOCOL_SUPPORT_ENUMERATION: lasso.SAML2_PROTOCOL_HREF }
        if self.role_descriptors.get('sp'):
            map, options = self.role_descriptors['sp']
            self.sp_descriptor = self.tb.start(self.SP_SSO_DESCRIPTOR, attrib)
            self.generate_services(map, options, self.sso_services)
            self.generate_services(map, {}, self.sp_services)
            self.tb.end(self.SP_SSO_DESCRIPTOR)
        if self.role_descriptors.get('idp'):
            map, options = self.role_descriptors['idp']
            self.sp_descriptor = self.tb.start(self.IDP_SSO_DESCRIPTOR, attrib)
            self.generate_services(map, options, self.sso_services)
            self.generate_services(map, {}, self.idp_services)
            self.tb.end(self.IDP_SSO_DESCRIPTOR)
        self.tb.end(self.ENTITY_DESCRIPTOR)
        return self.tb.close()

    def add_disco_extension(self, disco_return_url):
        self.tb.start(self.EXTENSIONS, {})
        self.tb.pushNamespace(self.DISCOVERY_NS)
        index = 0
        for url in disco_return_url:
            attrib = {'Binding': self.DISCOVERY_BINDING,
                'Location': self.url_prefix + url,
                'index': str(index)}
            self.tb.start(self.DISCOVERY_RESPONSE, attrib)
            self.tb.end(self.DISCOVERY_RESPONSE)
            index += 1
        self.tb.popNamespace()
        self.tb.end(self.EXTENSIONS)

    def __str__(self):
        return '<?xml version="1.0"?>\n' + etree.tostring(self.root_element())

def iso8601_to_datetime(date_string):
    '''Convert a string formatted as an ISO8601 date into a time_t value.

       This function ignores the sub-second resolution'''
    m = re.match(r'(\d+-\d+-\d+T\d+:\d+:\d+)(?:\.\d+)?Z$', date_string)
    if not m:
        raise ValueError('Invalid ISO8601 date')
    tm = time.strptime(m.group(1)+'Z', "%Y-%m-%dT%H:%M:%SZ")
    return datetime.datetime.fromtimestamp(time.mktime(tm))

def authnresponse_checking(login, subject_confirmation, logger, saml_request_id=None):
    logger.debug('beginning...')
    # If there is no inResponseTo: IDP initiated
    # else, check that the response id is the same
    assertion = login.assertion
    if not assertion:
        logger.error('Assertion missing')
        return False
    logger.debug('assertion %s' % assertion.dump())

    irt = None
    try:
        irt = assertion.subject. \
            subjectConfirmation.subjectConfirmationData.inResponseTo
    except:
        pass
    logger.debug('inResponseTo: %s' % irt)

    if irt and (not saml_request_id or saml_request_id != irt):
        logger.error('Request and Response ID do not match')
        return False

    # Check: SubjectConfirmation
    try:
        if assertion.subject.subjectConfirmation.method != \
                'urn:oasis:names:tc:SAML:2.0:cm:bearer':
            logger.error('Unknown \
                SubjectConfirmation Method')
            return False
    except:
        logger.error('Error checking \
            SubjectConfirmation Method')
        return False
    logger.debug('subjectConfirmation method known')

    # Check: Check that the url is the same as in the assertion
    try:
        if assertion.subject. \
                subjectConfirmation.subjectConfirmationData.recipient != \
                subject_confirmation:
            logger.error('SubjectConfirmation \
                Recipient Mismatch, %s is not %s' % (assertion.subject. \
                subjectConfirmation.subjectConfirmationData.recipient,
                subject_confirmation))
            return False
    except:
        logger.error('Error checking \
            SubjectConfirmation Recipient')
        return False
    logger.debug('\
        the url is the same as in the assertion')

    # Check: AudienceRestriction
    try:
        audience_ok = False
        for audience_restriction in assertion.conditions.audienceRestriction:
            if audience_restriction.audience != login.server.providerId:
                logger.error('Incorrect AudienceRestriction')
                return False
            audience_ok = True
        if not audience_ok:
            logger.error('Incorrect AudienceRestriction')
            return False
    except:
        logger.error('Error checking AudienceRestriction')
        return False
    logger.debug('audience restriction respected')

    # Check: notBefore, notOnOrAfter
    now = datetime.datetime.utcnow()
    try:
        not_before = assertion.subject. \
            subjectConfirmation.subjectConfirmationData.notBefore
    except:
        logger.error('missing subjectConfirmationData')
        return False

    not_on_or_after = assertion.subject.subjectConfirmation. \
        subjectConfirmationData.notOnOrAfter

    if irt:
        if not_before is not None:
            logger.error('assertion in response to an AuthnRequest, \
                notBefore MUST not be present in SubjectConfirmationData')
            return False
    elif not_before is not None and not not_before.endswith('Z'):
        logger.error('invalid notBefore value ' + not_before)
        return False
    if not_on_or_after is None or not not_on_or_after.endswith('Z'):
        logger.error('invalid notOnOrAfter format')
        return False
    try:
        if not_before and now < iso8601_to_datetime(not_before):
            logger.error('Assertion received too early')
            return False
    except:
        logger.error('invalid notBefore value ' + not_before)
        return False
    try:
        if not_on_or_after and now > iso8601_to_datetime(not_on_or_after):
            logger.error('Assertion expired')
            return False
    except:
        logger.error('invalid notOnOrAfter value')
        return False

    logger.debug('assertion validity timeslice respected \
        %s <= %s < %s ' % (not_before, str(now), not_on_or_after))

    return True

def get_attributes_from_assertion(assertion, logger):
    attributes = dict()
    if not assertion:
        return attributes
    for att_statement in assertion.attributeStatement:
        for attribute in att_statement.attribute:
            name = None
            format = lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC
            nickname = None
            try:
                name = attribute.name.decode('ascii')
            except:
                logger.warning('get_attributes_from_assertion: error decoding name of \
                    attribute %s' % attribute.dump())
            else:
                try:
                    if attribute.nameFormat:
                        format = attribute.nameFormat.decode('ascii')
                    if attribute.friendlyName:
                        nickname = attribute.friendlyName
                except Exception, e:
                    message = 'get_attributes_from_assertion: name or format of an \
                        attribute failed to decode as ascii: %s due to %s'
                    logger.warning(message % (attribute.dump(), str(e)))
                try:
                    values = attribute.attributeValue
                    if values:
                        attributes[(name, format)] = []
                        if nickname:
                            attributes[nickname] = attributes[(name, format)]
                    for value in values:
                        content = [any.exportToXml() for any in value.any]
                        content = ''.join(content)
                        attributes[(name, format)].append(content.\
                            decode('utf8'))
                except Exception, e:
                    message = 'get_attributes_from_assertion: value of an \
                        attribute failed to decode as ascii: %s due to %s'
                    logger.warning(message % (attribute.dump(), str(e)))
    attributes['__issuer'] = assertion.issuer.content
    attributes['__nameid'] = assertion.subject.nameID.content
    return attributes


if __name__ == '__main__':
    pkey, _ = x509utils.generate_rsa_keypair()
    meta = Saml2Metadata('http://example.com/saml', 'http://example.com/saml/prefix/')
    bindings2 = [ lasso.SAML2_METADATA_BINDING_SOAP,
            lasso.SAML2_METADATA_BINDING_REDIRECT,
            lasso.SAML2_METADATA_BINDING_POST ]
    options = { 'signing_key': pkey }
    meta.add_sp_descriptor((
        ('SingleLogoutService',
            lasso.SAML2_METADATA_BINDING_SOAP, 'logout', 'logoutReturn' ),
        ('ManageNameIDService',
            bindings2, 'manageNameID', 'manageNameIDReturn' ),
        ('AssertionConsumerService',
            [ lasso.SAML2_METADATA_BINDING_POST ], 'acs'),),
        options)
    root = meta.root_element()
    print etree.tostring(root)
