from optparse import make_option
import sys
import xml.etree.ElementTree as etree

import lasso
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.template.defaultfilters import slugify

from authentic2.saml.models import *


def md_element_name(tag_name):
    return '{%s}%s' % (lasso.SAML2_METADATA_HREF, tag_name)

ENTITY_DESCRIPTOR_TN = md_element_name('EntityDescriptor')
ENTITIES_DESCRIPTOR_TN = md_element_name('EntitiesDescriptor')
IDP_SSO_DESCRIPTOR_TN = md_element_name('IDPSSODescriptor')
SP_SSO_DESCRIPTOR_TN = md_element_name('SPSSODescriptor')
ORGANIZATION_DISPLAY_NAME = md_element_name('OrganizationDisplayName')
ORGANIZATION_NAME = md_element_name('OrganizationName')
ORGANIZATION = md_element_name('Organization')
ENTITY_ID = 'entityID'
PROTOCOL_SUPPORT_ENUMERATION = 'protocolSupportEnumeration'

def check_support_saml2(tree):
    if tree is not None and lasso.SAML2_PROTOCOL_HREF in tree.get(PROTOCOL_SUPPORT_ENUMERATION):
        return True
    return False

def load_one_entity(tree, options, sp_policy=None, idp_policy=None):
    '''Load or update an EntityDescriptor into the database'''
    entity_id = tree.get(ENTITY_ID)
    organization = tree.find(ORGANIZATION)
    name, org = None, None
    if organization is not None:
        organization_display_name = organization.find(ORGANIZATION_DISPLAY_NAME)
        organization_name = organization.find(ORGANIZATION_NAME)
        if organization_display_name is not None:
            name = organization_display_name.text
        elif organization_name is not None:
            name = organization_name.text
    if not name:
        name = entity_id
    idp, sp = False, False
    idp = check_support_saml2(tree.find(IDP_SSO_DESCRIPTOR_TN))
    sp = check_support_saml2(tree.find(SP_SSO_DESCRIPTOR_TN))
    if options.get('idp'):
        sp = False
    if options.get('sp'):
        idp = False
    if options.get('delete'):
        LibertyProvider.objects.filter(entity_id=entity_id).delete()
        print 'Deleted', entity_id
        return
    if idp or sp:
        # build an unique slug
        baseslug = slug = slugify(name)
        n = 1
        while LibertyProvider.objects.filter(slug=slug).exclude(entity_id=entity_id):
            n += 1
            slug = '%s-%d' % (baseslug, n)
        # get or create the provider
        provider, created = LibertyProvider.objects.get_or_create(entity_id=entity_id,
                protocol_conformance=3, defaults={'name': name, 'slug': slug})
        if options['verbosity'] == '2':
            if created:
                what = 'Creating'
            else:
                what = 'Updating'
            print '%(what)s %(name)s, %(id)s' % { 'what': what,
                    'name': name.encode('utf8'), 'id': entity_id}
        provider.name = name
        provider.metadata = etree.tostring(tree, encoding='utf-8').decode('utf-8').strip()
        provider.protocol_conformance = 3
        provider.federation_source = options['source']
        provider.save()
        options['count'] = options.get('count', 0) + 1
        if idp:
            identity_provider, created = LibertyIdentityProvider.objects.get_or_create(
                    liberty_provider=provider)
            identity_provider.enabled = True
            if idp_policy:
                identity_provider.idp_options_policy = idp_policy
            identity_provider.save()
        if sp:
            service_provider, created = LibertyServiceProvider.objects.get_or_create(
                    liberty_provider=provider)
            service_provider.enabled = True
            if sp_policy:
                service_provider.sp_options_policy = sp_policy
            service_provider.save()

class Command(BaseCommand):
    '''Load SAMLv2 metadata file into the LibertyProvider, LibertyServiceProvider
    and LibertyIdentityProvider files'''
    can_import_django_settings = True
    output_transaction = True
    requires_model_validation = True
    option_list = BaseCommand.option_list + (
        make_option('--idp',
            action='store_true',
            dest='idp',
            default=False,
            help='Load identity providers only'),
        make_option('--sp',
            action='store_true',
            dest='sp',
            default=False,
            help='Load service providers only'),
        make_option('--sp-policy',
            dest='sp_policy',
            default=None,
            help='SAML2 service provider options policy'),
        make_option('--idp-policy',
            dest='idp_policy',
            default=None,
            help='SAML2 identity provider options policy'),
        make_option('--delete',
            action='store_true',
            dest='delete',
            default=False,
            help='Delete all providers defined in the metadata file (kind of uninstall)'),
        make_option('--ignore-errors',
            action='store_true',
            dest='ignore-errors',
            default=False,
            help='If loading of one EntityDescriptor fails, continue loading'),
        make_option('--source',
            dest='source',
            default=None,
            help='Tag the loaded providers with the given source string, \
existing providers with the same tag will be removed if they do not exist\
 anymore in the metadata file.'),
        )
    args = '<metadata_file>'
    help = 'Load the specified SAMLv2 metadata file'

    @transaction.commit_manually
    def handle(self, *args, **options):
        source = options['source']
        try:
            if not args:
                raise CommandError('No metadata file on the command line')
            # Check sources
            try:
                if source is not None:
                    source.decode('ascii')
            except:
                raise CommandError('--source MUST be an ASCII string value')
            try:
                metadata_file = file(args[0])
            except:
                raise CommandError('Unable to open file %s' % args[0])
            try:
                doc = etree.parse(metadata_file)
            except Exception, e:
                raise CommandError('XML parsing error: %s' % str(e))
            if doc.getroot().tag == ENTITY_DESCRIPTOR_TN:
                load_one_entity(doc.getroot(), options)
            elif doc.getroot().tag == ENTITIES_DESCRIPTOR_TN:
                sp_policy = None
                if 'sp_policy' in options and options['sp_policy']:
                    sp_policy_name = options['sp_policy']
                    try:
                        sp_policy = SPOptionsIdPPolicy.objects.get(name=sp_policy_name)
                        print 'Service providers are set with the following SAML2 \
                            options policy: %s' % sp_policy
                    except:
                        print 'SAML2 service provider options policy with name %s not found' % sp_policy_name
                else:
                    print 'No SAML2 service provider options policy provided'
                idp_policy = None
                if 'idp_policy' in options and options['idp_policy']:
                    idp_policy_name = options['idp_policy']
                    try:
                        idp_policy = IdPOptionsSPPolicy.objects.get(name=idp_policy_name)
                        print 'Identity providers are set with the following SAML2 \
                            options policy: %s' % idp_policy
                    except:
                        print 'SAML2 identity provider options policy with name %s not found' % idp_policy_name
                else:
                    print 'No SAML2 identity provider options policy provided'
                loaded = []
                if doc.getroot().tag == ENTITY_DESCRIPTOR_TN:
                    entity_descriptors = [ doc.getroot() ]
                else:
                    entity_descriptors = doc.getroot().findall(ENTITY_DESCRIPTOR_TN)
                for entity_descriptor in entity_descriptors:
                    try:
                        load_one_entity(entity_descriptor, options, sp_policy=sp_policy, idp_policy=idp_policy)
                        loaded.append(entity_descriptor.get(ENTITY_ID))
                    except Exception, e:
                        raise
                        entity_id = entity_descriptor.get(ENTITY_ID)
                        if options['ignore-errors']:
                            print >> sys.stderr, 'Unable to load EntityDescriptor for %s: %s' % (entity_id, str(e))
                        else:
                            raise CommandError('EntityDescriptor loading: %s' % str(e))
                if options['source']:
                    if options['delete']:
                        print 'Finally delete all providers for source: %s...' % source
                        LibertyProvider.objects.filter(federation_source=source).delete()
                    else:
                        to_delete = LibertyProvider.objects.filter(federation_source=source)\
                                .exclude(entity_id__in=loaded)
                        for provider in to_delete:
                            print 'Delete obsolete provider %s' % provider.entity_id
                            provider.delete()
            else:
                raise CommandError('%s is not a SAMLv2 metadata file' % metadata_file)
        except:
            transaction.rollback()
            raise
        else:
            transaction.commit()
        if not options.get('delete'):
            print 'Loaded', options.get('count', 0), 'providers'
