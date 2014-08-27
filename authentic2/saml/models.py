import xml.etree.ElementTree as etree
import hashlib
import numbers
import datetime

import lasso
from django.db import models
from django.db.models import Q
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.contenttypes.models import ContentType
try:
    from django.contrib.contenttypes.fields import GenericForeignKey
except ImportError:
    from django.contrib.contenttypes.generic import GenericForeignKey
try:
    from django.contrib.contenttypes.fields import GenericRelation
except ImportError:
    from django.contrib.contenttypes.generic import GenericRelation


from fields import PickledObjectField, MultiSelectField

from . import app_settings, managers
from .. import managers as a2_managers

def metadata_validator(meta):
    provider=lasso.Provider.newFromBuffer(lasso.PROVIDER_ROLE_ANY, meta.encode('utf8'))
    if not provider:
        raise ValidationError(_('Invalid metadata file'))
XML_NS = 'http://www.w3.org/XML/1998/namespace'

def get_lang(etree):
    return etree.get('{%s}lang' % XML_NS)

def ls_find(ls, value):
    try:
        return ls.index(value)
    except ValueError:
        return -1

def get_prefered_content(etrees, languages = [None, 'en']):
    '''Sort XML nodes by their xml:lang attribute using languages as the
    ascending partial order of language identifiers

       Default is to prefer english, then no lang declaration, to anything
       else.
    '''
    best = None
    best_score = -1
    for tree in etrees:
        if best is not None:
            i = ls_find(languages, get_lang(tree))
            if i > best_score:
                best = tree
                best_score = ls_find(languages, get_lang(tree))
        else:
            best = tree
            best_score = ls_find(languages, get_lang(tree))
    return best.text

def organization_name(provider):
    '''Extract an organization name from a SAMLv2 metadata organization XML
       fragment.
    '''
    try:
        organization_xml = provider.organization
        organization = etree.XML(organization_xml)
        o_display_name = organization.findall('{%s}OrganizationDisplayName' %
                lasso.SAML2_METADATA_HREF)
        if o_display_name:
            return get_prefered_content(o_display_name)
        o_name = organization.findall('{%s}OrganizationName' %
                lasso.SAML2_METADATA_HREF)
        if o_name:
            return get_prefered_content(o_name)
    except:
        return provider.providerId
    else:
        return provider.providerId

# TODO: Remove this in LibertyServiceProvider
ASSERTION_CONSUMER_PROFILES = (
        ('meta', _('Use the default from the metadata file')),
        ('art', _('Artifact binding')),
        ('post', _('POST binding')))

DEFAULT_NAME_ID_FORMAT = 'none'

# Supported name id formats
NAME_ID_FORMATS = {
        'none': { 'caption': _('None'),
            'samlv2': None,},
        'persistent': { 'caption': _('Persistent'),
            'samlv2': lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT,},
        'transient': { 'caption': _("Transient"),
            'samlv2': lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT,},
        'email': { 'caption': _("Email"),
            'samlv2': lasso.SAML2_NAME_IDENTIFIER_FORMAT_EMAIL,},
        'username': { 'caption': _("Username (use with Google Apps)"),
            'samlv2': lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED,},
        'edupersontargetedid': { 'caption': _("Use eduPersonTargetedID attribute"),
            'samlv2': lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT,}
}

NAME_ID_FORMATS_CHOICES = \
        tuple([(x, y['caption']) for x, y in NAME_ID_FORMATS.iteritems()])

ACCEPTED_NAME_ID_FORMAT_LENGTH = \
        sum([len(x) for x, y in NAME_ID_FORMATS.iteritems()]) + \
        len(NAME_ID_FORMATS) - 1

def saml2_urn_to_nidformat(urn):
    for x, y in NAME_ID_FORMATS.iteritems():
        if y['samlv2'] == urn:
            return x
    return None

def nidformat_to_saml2_urn(key):
    return NAME_ID_FORMATS.get(key, {}).get('samlv2')

# According to: saml-profiles-2.0-os
# The HTTP Redirect binding MUST NOT be used, as the response will typically exceed the URL length permitted by most user agents.
BINDING_SSO_IDP = (
    (lasso.SAML2_METADATA_BINDING_ARTIFACT, _('Artifact binding')),
    (lasso.SAML2_METADATA_BINDING_POST, _('POST binding'))
)


HTTP_METHOD = (
    (lasso.HTTP_METHOD_REDIRECT, _('Redirect binding')),
    (lasso.HTTP_METHOD_SOAP, _('SOAP binding'))
)


SIGNATURE_VERIFY_HINT = {
        lasso.PROFILE_SIGNATURE_VERIFY_HINT_MAYBE: _('Let authentic decides which signatures to check'),
        lasso.PROFILE_SIGNATURE_VERIFY_HINT_FORCE: _('Always check signatures'),
        lasso.PROFILE_SIGNATURE_VERIFY_HINT_IGNORE: _('Does not check signatures') }

class LibertyProviderPolicy(models.Model):
    name = models.CharField(max_length=64, unique=True)
    authn_request_signature_check_hint = models.IntegerField(
            verbose_name=_("How to verify signatures Authentication Request ?"),
            choices=SIGNATURE_VERIFY_HINT.items(),
            default=lasso.PROFILE_SIGNATURE_VERIFY_HINT_MAYBE)

    def __unicode__(self):
        options = []
        options.append(u'AuthnRequest signature: %s' % SIGNATURE_VERIFY_HINT[self.authn_request_signature_check_hint])
        return self.name + ' (%s)' % ', '.join(options)

    class Meta:
        verbose_name = _('SAML service provider policy')
        verbose_name_plural = _('SAML service provider policies')


AUTHSAML2_UNAUTH_PERSISTENT = (
    ('AUTHSAML2_UNAUTH_PERSISTENT_ACCOUNT_LINKING_BY_AUTH',
        _('Account linking by authentication')),
    ('AUTHSAML2_UNAUTH_PERSISTENT_CREATE_USER_PSEUDONYMOUS',
        _('Create new account')),
)

AUTHSAML2_UNAUTH_TRANSIENT = (
    ('AUTHSAML2_UNAUTH_TRANSIENT_ASK_AUTH', _('Ask authentication')),
    ('AUTHSAML2_UNAUTH_TRANSIENT_OPEN_SESSION', _('Open a session')),
)


class IdPOptionsSPPolicy(models.Model):
    '''
        Policies configured as a SAML2 service provider.

        Used to define SAML2 parameters employed with third SAML2 identity
        providers
    '''
    name = models.CharField(_('name'), max_length=200, unique=True)
    enabled = models.BooleanField(verbose_name = _('Enabled'))
    no_nameid_policy = models.BooleanField(
            verbose_name = _("Do not send a nameId Policy"))
    requested_name_id_format = models.CharField(
            verbose_name = _("Requested NameID format"),
            max_length = 200,
            default = DEFAULT_NAME_ID_FORMAT,
            choices = NAME_ID_FORMATS_CHOICES)
    transient_is_persistent = models.BooleanField(
            verbose_name = \
_("This IdP sends a transient NameID but you want a persistent behaviour for your SP"))
    persistent_identifier_attribute = models.CharField(_('Persistent '
            'identifier attribute'), max_length=200, null=True, blank=True)
    allow_create = models.BooleanField(
            verbose_name = _("Allow IdP to create an identity"))
    enable_binding_for_sso_response = models.BooleanField(
            verbose_name = _('Binding for Authnresponse \
            (taken from metadata by the IdP if not enabled)'))
    binding_for_sso_response = models.CharField(
            verbose_name = _("Binding for the SSO responses"),
            max_length = 200, choices = BINDING_SSO_IDP,
            default = lasso.SAML2_METADATA_BINDING_ARTIFACT)
    enable_http_method_for_slo_request = models.BooleanField(
            verbose_name = _('HTTP method for single logout request \
            (taken from metadata if not enabled)'))
    http_method_for_slo_request = models.IntegerField(
            verbose_name = _("HTTP binding for the SLO requests"),
            max_length = 200, choices = HTTP_METHOD,
            default = lasso.HTTP_METHOD_REDIRECT)
    enable_http_method_for_defederation_request = models.BooleanField(
            verbose_name = \
            _('HTTP method for federation termination request \
            (taken from metadata if not enabled)'))
    http_method_for_defederation_request = models.IntegerField(
            verbose_name = _("HTTP method for the defederation requests"),
            max_length = 200, choices = HTTP_METHOD,
            default = lasso.HTTP_METHOD_SOAP)
    force_user_consent = models.BooleanField(\
            verbose_name = \
                _("Require the user consent be given at account linking"),
            default=False)
    want_force_authn_request = models.BooleanField(
            verbose_name = _("Force authentication"))
    want_is_passive_authn_request = models.BooleanField(
            verbose_name = _("Passive authentication"))
    want_authn_request_signed = models.BooleanField(
            verbose_name = _("Want AuthnRequest signed"))
    handle_persistent = models.CharField(
            max_length=200,
            verbose_name = _('Behavior with persistent NameID'),
            choices=AUTHSAML2_UNAUTH_PERSISTENT,
            default = 'AUTHSAML2_UNAUTH_PERSISTENT_ACCOUNT_LINKING_BY_AUTH')
    handle_transient = models.CharField(
            max_length=200,
            verbose_name = _('Behavior with transient NameID'),
            choices=AUTHSAML2_UNAUTH_TRANSIENT,
            default = '')
    back_url = models.CharField(
            max_length = 200,
            default = '/',
            verbose_name = _('Return URL after a successful authentication'))
    accept_slo = models.BooleanField(\
            verbose_name = _("Accept to receive Single Logout requests"),
            default=True)
    forward_slo = models.BooleanField(\
            verbose_name = _("Forward Single Logout requests"),
            default=True)

    class Meta:
        verbose_name = _('identity provider options policy')
        verbose_name_plural = _('identity provider options policies')

    def __unicode__(self):
        return self.name


class SPOptionsIdPPolicy(models.Model):
    '''
        Policies configured as a SAML2 identity provider.

        Used to define SAML2 parameters employed with service providers.
    '''
    name = models.CharField(_('name'), max_length=80, unique=True)
    enabled = models.BooleanField(verbose_name = _('Enabled'))
    prefered_assertion_consumer_binding = models.CharField(
            verbose_name = _("Prefered assertion consumer binding"),
            default = 'meta',
            max_length = 4, choices = ASSERTION_CONSUMER_PROFILES)
    encrypt_nameid = models.BooleanField(verbose_name = _("Encrypt NameID"))
    encrypt_assertion = models.BooleanField(
            verbose_name = _("Encrypt Assertion"))
    authn_request_signed = models.BooleanField(
            verbose_name = _("Authentication request signed"))
    idp_initiated_sso = models.BooleanField(
            verbose_name = _("Allow IdP initiated SSO"))
    # XXX: format in the metadata file, should be suffixed with a star to mark
    # them as special
    default_name_id_format = models.CharField(max_length = 256,
            default = DEFAULT_NAME_ID_FORMAT,
            choices = NAME_ID_FORMATS_CHOICES)
    accepted_name_id_format = MultiSelectField(
            verbose_name = _("NameID formats accepted"),
            max_length=1024,
            blank=True, choices=NAME_ID_FORMATS_CHOICES)
    # TODO: add clean method which checks that the LassoProvider we can create
    # with the metadata file support the SP role
    # i.e. provider.roles & lasso.PROVIDER_ROLE_SP != 0
    ask_user_consent = models.BooleanField(
        verbose_name = _('Ask user for consent when creating a federation'), default = False)
    accept_slo = models.BooleanField(\
            verbose_name = _("Accept to receive Single Logout requests"),
            default=True)
    forward_slo = models.BooleanField(\
            verbose_name = _("Forward Single Logout requests"),
            default=True)
    needs_iframe_logout = models.BooleanField(
            verbose_name=_('needs iframe logout'),
            help_text=_('logout URL are normally loaded inside an <img> HTML tag, some service provider need to use an iframe'),
            default=False)
    iframe_logout_timeout = models.PositiveIntegerField(
            verbose_name=_('iframe logout timeout'),
            help_text=_('if iframe logout is used, it\'s the time between the '
                'onload event for this iframe and the moment we consider its '
                'loading to be really finished'),
            default=300)
    http_method_for_slo_request = models.IntegerField(
            verbose_name = _("HTTP binding for the SLO requests"),
            choices = HTTP_METHOD, default = lasso.HTTP_METHOD_REDIRECT)
    federation_mode = models.PositiveIntegerField(_('federation mode'),
            choices=app_settings.FEDERATION_MODE.get_choices(app_settings),
            default=app_settings.FEDERATION_MODE.get_default(app_settings))
    attributes = GenericRelation('SAMLAttribute')

    class Meta:
        verbose_name = _('service provider options policy')
        verbose_name_plural = _('service provider options policies')

    def __unicode__(self):
        return self.name

class SAMLAttribute(models.Model):
    ATTRIBUTE_NAME_FORMATS = (
            ('basic', 'Basic'),
            ('uri', 'URI'),
    )
    objects = a2_managers.GenericManager()

    content_type = models.ForeignKey(ContentType,
            verbose_name=_('content type'))
    object_id = models.PositiveIntegerField(
            verbose_name=_('object identifier'))
    provider = GenericForeignKey('content_type', 'object_id')
    name_format = models.CharField(
            max_length=64,
            verbose_name=_('name format'),
            default='basic',
            choices=ATTRIBUTE_NAME_FORMATS)
    name = models.CharField(
            max_length=64,
            verbose_name=_('name'),
            blank=True,
            help_text=_('the local attribute name is used if left blank'))
    friendly_name = models.CharField(
            max_length=64,
            verbose_name=_('friendly name'),
            blank=True)
    attribute_name = models.CharField(max_length=64,
            verbose_name=_('attribute name'))

    def clean(self):
        super(SAMLAttribute, self).clean()
        if self.attribute_name and not self.name:
            self.name = self.attribute_name

    def name_format_uri(self):
        if self.name_format == 'basic':
            return lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC
        elif self.name.format == 'uri':
            return lasso.SAML2_ATTRIBUTE_NAME_FORMAT_URI
        else:
            raise NotImplementedError

    def to_lasso_attribute(self, ctx):
        if not self.attribute_name in ctx:
            return None
        at = lasso.Saml2Attribute()
        at.nameFormat = self.name_format_uri()
        at.name = self.name.encode('utf-8')
        if self.friendly_name:
            at.friendlyName = self.friendly_name.encode('utf-8')
        values = ctx.get(self.attribute_name)
        if isinstance(values, (basestring, numbers.Number, datetime.datetime, datetime.date)):
            values = [values]
        elif isinstance(values, (tuple, list)):
            pass
        else:
            raise NotImplementedError
        atvs = []
        for value in values:
            atv = lasso.Saml2AttributeValue()
            value = value.encode('utf-8')
            tn = lasso.MiscTextNode.newWithString(value)
            tn.textChild = True
            atv.any = [tn]
            atvs.append(atv)
        at.attributeValue = atvs
        return at

    def __unicode__(self):
        ctx = {self.attribute_name: 'coin'}
        return unicode(self.to_lasso_attribute(ctx).exportToXml(), 'utf-8')



class AuthorizationAttributeMap(models.Model):
    name = models.CharField(max_length = 40, unique = True)
    def __unicode__(self):
        return self.name

    class Meta:
        verbose_name = _('authorization attribute map')
        verbose_name_plural = _('authorization attribute maps')

class AuthorizationAttributeMapping(models.Model):
    source_attribute_name = models.CharField(max_length = 40,
            blank=True)
    attribute_value_format = models.CharField(max_length = 40,
            blank=True)
    attribute_name = models.CharField(max_length = 40)
    attribute_value = models.CharField(max_length = 40)
    map = models.ForeignKey(AuthorizationAttributeMap)

    class Meta:
        verbose_name = _('authorization attribute mapping')
        verbose_name_plural = _('authorization attribute mappings')

class AuthorizationSPPolicy(models.Model):
    name = models.CharField(_('name'), max_length=80, unique=True)
    enabled = models.BooleanField(verbose_name = _('Enabled'))
    attribute_map = models.ForeignKey(AuthorizationAttributeMap,
            related_name = "authorization_attributes",
            blank = True, null = True)
    default_denial_message = models.CharField(
            max_length = 80,
            verbose_name = \
            _("Default message to display to the user when access is denied"),
            default=_('You are not authorized to access the service.'))

    class Meta:
        verbose_name = _('authorization identity providers policy')
        verbose_name_plural = _('authorization identity providers policies')

    def __unicode__(self):
        return self.name


class LibertyProvider(models.Model):
    name = models.CharField(max_length = 140,
            help_text = _("Internal nickname for the service provider"),
            blank = True)
    slug = models.SlugField(max_length=140, unique=True)
    entity_id = models.URLField(unique = True)
    entity_id_sha1 = models.CharField(max_length = 40, blank=True)
    protocol_conformance = models.IntegerField(max_length = 10,
            choices = ((lasso.PROTOCOL_SAML_2_0, 'SAML 2.0'),))
    metadata = models.TextField(validators = [ metadata_validator ])
    # All following field must be PEM formatted textual data
    public_key = models.TextField(blank=True)
    ssl_certificate = models.TextField(blank=True)
    ca_cert_chain = models.TextField(blank=True)
    federation_source = models.CharField(max_length=64, blank=True, null=True)

    objects = managers.LibertyProviderManager()

    def __unicode__(self):
        return self.name

    def save(self, *args, **kwargs):
        '''Update the SHA1 hash of the entity_id when saving'''
        if self.protocol_conformance == 3:
            self.entity_id_sha1 = hashlib.sha1(self.entity_id).hexdigest()
        super(LibertyProvider, self).save(*args, **kwargs)

    def clean(self):
        super(LibertyProvider, self).clean()
        p = lasso.Provider.newFromBuffer(lasso.PROVIDER_ROLE_ANY, self.metadata.encode('utf8'))
        if p is None:
            raise ValidationError(_('Invalid metadata file'))
        self.entity_id = p.providerId
        if not self.name:
            self.name = organization_name(p)
        self.protocol_conformance = p.protocolConformance
        if self.protocol_conformance != lasso.PROTOCOL_SAML_2_0:
            raise ValidationError(_('Protocol other than SAML 2.0 are unsupported'))

    def natural_key(self):
        return (self.slug,)

    class Meta:
        ordering = ('name',)
        verbose_name = _('SAML provider')
        verbose_name_plural = _('SAML providers')

def get_all_custom_or_default(instance, name):
    model = instance._meta.get_field_by_name(name)[0].rel.to
    try:
        return model.objects.get(name='All')
    except ObjectDoesNotExist:
        pass
    custom = getattr(instance, name, None)
    if custom is not None:
        return custom
    try:
        return models.objects.get(name='Default')
    except ObjectDoesNotExist:
        raise RuntimeError('Default %s is missing' % model)

# TODO: The IdP must look to the preferred binding order for sso in the SP metadata (AssertionConsumerService)
# expect if the protocol for response is defined in the request (ProtocolBinding attribute)
class LibertyServiceProvider(models.Model):
    liberty_provider = models.OneToOneField(LibertyProvider,
            primary_key = True, related_name = 'service_provider')
    enabled = models.BooleanField(verbose_name = _('Enabled'))
    enable_following_sp_options_policy = models.BooleanField(verbose_name = \
        _('The following options policy will apply except if a policy for all service provider is defined.'))
    sp_options_policy = models.ForeignKey(SPOptionsIdPPolicy, related_name = "sp_options_policy", verbose_name = _('service provider options policy'), blank=True, null=True)
    policy = models.ForeignKey(LibertyProviderPolicy,
            verbose_name=_("Protocol policy"), null=True, default=1)
    enable_following_attribute_policy = models.BooleanField(verbose_name = \
        _('The following attribute policy will apply except if a policy for all service provider is defined.'))
    attribute_policy = models.ForeignKey('idp.AttributePolicy',
             related_name = "attribute_policy",
            verbose_name=_("attribute policy"), null=True, blank=True)

    objects = managers.GetByLibertyProviderManager()

    def get_policy(self):
        return get_all_custom_or_default(self, 'policy')

    def natural_key(self):
        return (self.liberty_provider.slug,)

    def __unicode__(self):
        return unicode(self.liberty_provider)

    class Meta:
        verbose_name = _('SAML service provider')
        verbose_name_plural = _('SAML service providers')


# TODO: The choice for requests must be restricted by the IdP metadata
# The SP then chooses the binding in this list.
# For response, if the requester uses a (a)synchronous binding, the responder uses the same.
# However, the responder can choose which asynchronous binding it employs.
class LibertyIdentityProvider(models.Model):
    liberty_provider = models.OneToOneField(LibertyProvider,
            primary_key = True, related_name = 'identity_provider')
    enabled = models.BooleanField(verbose_name = _('Enabled'))
    enable_following_idp_options_policy = models.BooleanField(verbose_name = \
        _('The following options policy will apply except if a policy for all '
          'identity provider is defined.'))
    idp_options_policy = models.ForeignKey(IdPOptionsSPPolicy,
            related_name="idp_options_policy",
            verbose_name=_('identity provider options policy'), blank=True,
            null=True)
    enable_following_authorization_policy = models.BooleanField(verbose_name = \
        _('The following authorization policy will apply except if a policy for'
          ' all identity provider is defined.'))
    authorization_policy = models.ForeignKey(AuthorizationSPPolicy,
            related_name="authorization_policy",
            verbose_name=_('authorization identity providers policy'), blank=True, null=True)

    objects = managers.GetByLibertyProviderManager()

    # TODO: add clean method which checks that the LassoProvider we can create
    # with the metadata file support the IDP role
    # i.e. provider.roles & lasso.PROVIDER_ROLE_IDP != 0

    def __unicode__(self):
        return unicode(self.liberty_provider)

    def natural_key(self):
        return (self.liberty_provider.slug,)

    class Meta:
        verbose_name = _('SAML identity provider')
        verbose_name_plural = _('SAML identity providers')

LIBERTY_SESSION_DUMP_KIND_SP = 0
LIBERTY_SESSION_DUMP_KIND_IDP = 1
LIBERTY_SESSION_DUMP_KIND = { LIBERTY_SESSION_DUMP_KIND_SP: 'sp',
        LIBERTY_SESSION_DUMP_KIND_IDP: 'idp' }

class LibertySessionDump(models.Model):
    '''Store lasso session object dump.

       Should be replaced in the future by direct references to known
       assertions through the LibertySession object'''
    django_session_key = models.CharField(max_length = 128)
    session_dump = models.TextField(blank = True)
    kind = models.IntegerField(choices = LIBERTY_SESSION_DUMP_KIND.items())

    objects = managers.SessionLinkedManager()

    class Meta:
        verbose_name = _('SAML session dump')
        verbose_name_plural = _('SAML session dumps')

class LibertyManageDump(models.Model):
    '''Store lasso manage dump

       Should be replaced in the future by direct reference to ?
       objects'''
    django_session_key = models.CharField(max_length = 128)
    manage_dump = models.TextField(blank = True)

    objects = managers.SessionLinkedManager()

    class Meta:
        verbose_name = _('SAML manage dump')
        verbose_name_plural = _('SAML manage dumps')

class LibertyArtifact(models.Model):
    """Store an artifact and the associated XML content"""
    creation = models.DateTimeField(auto_now_add=True)
    artifact = models.CharField(max_length = 128, primary_key = True)
    content = models.TextField()
    provider_id = models.CharField(max_length = 256)

    objects = managers.LibertyArtifactManager()

    class Meta:
        verbose_name = _('SAML artifact')
        verbose_name_plural = _('SAML artifacts')

def nameid2kwargs(name_id):
    return {
        'name_id_qualifier': name_id.nameQualifier,
        'name_id_sp_name_qualifier': name_id.spNameQualifier,
        'name_id_content': name_id.content,
        'name_id_format': name_id.format }

class LibertyAssertion(models.Model):
    assertion_id = models.CharField(max_length = 128)
    provider_id = models.CharField(max_length = 256)
    session_index = models.CharField(max_length = 128, )
    assertion = models.TextField()
    creation = models.DateTimeField(auto_now_add=True)

    def __init__(self, *args, **kwargs):
        saml2_assertion = kwargs.pop('saml2_assertion', None)
        if saml2_assertion:
            kwargs['assertion_id'] = saml2_assertion.id
            kwargs['session_index'] = \
                    saml2_assertion.authnStatement[0].sessionIndex
            kwargs['assertion'] = saml2_assertion.exportToXml()
        models.Model.__init__(self, *args, **kwargs)

    class Meta:
        verbose_name = _('SAML assertion')
        verbose_name_plural = _('SAML assertions')

# XXX: for retrocompatibility
federation_delete = managers.federation_delete

class LibertyFederation(models.Model):
    """Store a federation, i.e. an identifier shared with another provider, be
       it IdP or SP"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
            on_delete=models.SET_NULL)
    idp = models.ForeignKey('LibertyIdentityProvider', null=True, blank=True)
    sp = models.ForeignKey('LibertyServiceProvider', null=True, blank=True)
    name_id_format = models.CharField(max_length = 100,
            verbose_name = "NameIDFormat", blank=True, null=True)
    name_id_content = models.CharField(max_length = 100,
            verbose_name = "NameID")
    name_id_qualifier = models.CharField(max_length = 256,
            verbose_name = "NameQualifier", blank=True, null=True)
    name_id_sp_name_qualifier = models.CharField(max_length = 256,
            verbose_name = "SPNameQualifier", blank=True, null=True)
    termination_notified = models.BooleanField(blank=True, default=False)
    creation = models.DateTimeField(auto_now_add=True)
    last_modification = models.DateTimeField(auto_now=True)

    objects = managers.LibertyFederationManager()

    def __init__(self, *args, **kwargs):
        saml2_assertion = kwargs.pop('saml2_assertion', None)
        if saml2_assertion:
            name_id = saml2_assertion.subject.nameID
            kwargs.update(nameid2kwargs(name_id))
        models.Model.__init__(self, *args, **kwargs)

    def natural_key(self):
        key = self.user.natural_key()
        if self.sp:
            key += self.sp.natural_key()
        else:
            key += (None,)
        if self.idp:
            key += self.idp.natural_key()
        else:
            key += (None,)
        return key


    def is_unique(self, for_format=True):
        '''Return whether a federation already exist for this user and this provider.

           By default the check is made by name_id_format, if you want to check
           whatever the format, set for_format to False.
        '''
        qs = LibertyFederation.objects.exclude(id=self.id) \
                .filter(user=self.user, idp=self.idp, sp=self.sp)
        if for_format:
            qs = qs.filter(name_id_format=self.name_id_format)
        return not qs.exists()

    class Meta:
        verbose_name = _("SAML federation")
        verbose_name_plural = _("SAML federations")

    def __unicode__(self):
        return self.name_id_content


class LibertySession(models.Model):
    """Store the link between a Django session and a SAML session"""
    django_session_key = models.CharField(max_length = 128)
    session_index = models.CharField(max_length = 80)
    provider_id = models.CharField(max_length = 256)
    federation = models.ForeignKey(LibertyFederation, blank=True,
            null = True)
    assertion = models.ForeignKey(LibertyAssertion, blank=True, null
            = True)
    name_id_qualifier = models.CharField(max_length = 256,
            verbose_name = _("Qualifier"), null = True)
    name_id_format = models.CharField(max_length = 100,
            verbose_name = _("NameIDFormat"), null = True)
    name_id_content = models.CharField(max_length = 100,
            verbose_name = _("NameID"))
    name_id_sp_name_qualifier = models.CharField(max_length = 256,
            verbose_name = _("SPNameQualifier"), null = True)
    creation = models.DateTimeField(auto_now_add=True)

    objects = managers.LibertySessionManager()

    def __init__(self, *args, **kwargs):
        saml2_assertion = kwargs.pop('saml2_assertion', None)
        if saml2_assertion:
            kwargs['session_index'] = \
                saml2_assertion.authnStatement[0].sessionIndex
            name_id = saml2_assertion.subject.nameID
            kwargs.update(nameid2kwargs(name_id))
        models.Model.__init__(self, *args, **kwargs)

    def set_nid(self, name_id):
        self.__dict__.update(nameid2kwargs(name_id))

    @classmethod
    def get_for_nameid_and_session_indexes(cls, issuer_id, provider_id, name_id, session_indexes):
        kwargs = nameid2kwargs(name_id)
        name_id_qualifier = kwargs['name_id_qualifier']
        qs = LibertySession.objects.filter(provider_id=provider_id,
                session_index__in=session_indexes)
        if name_id_qualifier and name_id_qualifier != issuer_id:
            qs = qs.filter(**kwargs)
        else:
            kwargs.pop('name_id_qualifier')
            qs = qs.filter(**kwargs) \
                    .filter(Q(name_id_qualifier__isnull=True)|Q(name_id_qualifier=issuer_id))
        qs = qs.filter(Q(name_id_sp_name_qualifier__isnull=True)|Q(name_id_sp_name_qualifier=provider_id))
        return qs

    def __unicode__(self):
        return '<LibertySession %s>' % self.__dict__

    class Meta:
        verbose_name = _("SAML session")
        verbose_name_plural = _("SAML sessions")

class LibertySessionSP(models.Model):
    """Store the link between a Django session and a SAML session on the SP"""
    django_session_key = models.CharField(max_length = 128)
    session_index =  models.CharField(max_length = 80, )
    federation = models.ForeignKey(LibertyFederation)

    class Meta:
        verbose_name = _("SAML service provider session")
        verbose_name_plural = _("SAML service provider sessions")

class KeyValue(models.Model):
    key = models.CharField(max_length=128, primary_key=True)
    value = PickledObjectField()

    def __unicode__(self):
        return self.key

    class Meta:
        verbose_name = _("key value association")
        verbose_name_plural = _("key value associations")

def save_key_values(key, *values):
    KeyValue(key = key, value = values).save()

def get_and_delete_key_values(key):
    try:
        kv = KeyValue.objects.get(key=key)
        return kv.value
    except ObjectDoesNotExist:
        return None
