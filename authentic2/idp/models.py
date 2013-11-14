
from django.db import models
from django.utils.translation import ugettext_lazy as _

import lasso

from authentic2.attribute_aggregator.mapping_loader import ATTRIBUTE_NAMESPACES

ATTRIBUTES_NS = [('Default', 'Default')] \
    + [(ns, ns) for ns in ATTRIBUTE_NAMESPACES]

ATTRIBUTE_VALUE_FORMATS = (
        (lasso.SAML2_ATTRIBUTE_NAME_FORMAT_URI, 'SAMLv2 URI'),
        (lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC, 'SAMLv2 BASIC'))

class AttributePolicy(models.Model):
    name = models.CharField(max_length = 100, unique = True)
    enabled = models.BooleanField(verbose_name = _('Enabled'))
    ask_consent_attributes = models.BooleanField(\
            verbose_name = _("Ask the user consent before forwarding attributes"),
            default=True)
    allow_attributes_selection = models.BooleanField(\
            verbose_name = _("Allow the user to select the forwarding attributes"),
            default=True)
    # List of attributes to provide from pull sources at SSO Login.
    # If an attribute is indicate without a source, from any source.
    # The output format and namespace is given by each attribute.
    attribute_list_for_sso_from_pull_sources = \
        models.ForeignKey('attribute_aggregator.AttributeList',
        verbose_name = _("Pull attributes list"),
        related_name = "attributes from pull sources",
        blank = True, null = True)

    # Set to true for proxying attributes from pull sources at SSO Login.
    # Attributes are in session.
    # All attributes are forwarded as is except if the parameter
    # 'map_attributes_from_push_sources' is initialized
    forward_attributes_from_push_sources = models.BooleanField(
        verbose_name = _("Forward pushed attributes"),
        default=False)

    # Map attributes in session
    # forward_attributes_in_session must be true
    # At False, all attributes are forwarded as is
    # At true, look for the namespace of the source for input, If not found,
    # system namespace. Look for the options attribute_name_format and
    # output_namespace of the attribute policy for output.
    map_attributes_from_push_sources = models.BooleanField(
        verbose_name = _("Map forwarded pushed attributes"),
        default=False)

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

    # Filter attributes pushed from source.
    source_filter_for_sso_from_push_sources = \
        models.ManyToManyField('attribute_aggregator.AttributeSource',
        verbose_name = \
            _("Filter by source the forwarded pushed attributes"),
        related_name = "filter attributes of push sources with sources",
        blank = True, null = True)

    # List of attributes to filter from push sources at SSO Login.
    attribute_filter_for_sso_from_push_sources = \
        models.ForeignKey('attribute_aggregator.AttributeList',
        verbose_name = \
            _("Filter by attribute names the forwarded pushed attributes"),
        related_name = "filter attributes of push sources with list",
        blank = True, null = True)

    # The sources of attributes of the previous list are considered.
    # May be used conjointly with 'source_filter_for_sso_from_push_sources'
    filter_source_of_filtered_attributes = models.BooleanField(
        verbose_name = \
    _("Filter by source and per attribute the forwarded pushed attributes"),
        default=False)

    # To map the attributes of forwarded attributes with the defaut output
    # format and namespace, use 'map_attributes_from_pull_sources'
    # Use the following option to use the output format and namespace
    # indicated for each attribute.
    map_attributes_of_filtered_attributes = models.BooleanField(
        verbose_name = _("Map filtered attributes"),
        default=False)

    # Set to true to take in account missing required attributes
    send_error_and_no_attrs_if_missing_required_attrs = \
        models.BooleanField(
        verbose_name = \
            _("Send an error when a required attribute is missing"),
        default=False)

    # Ask user consent
    #ask_user_consent = models.BooleanField(default=False)

    class Meta:
        verbose_name = _('attribute policy')
        verbose_name_plural = _('attribute policies')

    def __unicode__(self):
        return self.name

    def __repr__(self):
        return '<AttributePolicy {0!r}>'.format(self.__dict__)



def get_attribute_policy(provider):
    try:
        return AttributePolicy.objects.get(name='All', enabled=True)
    except AttributePolicy.DoesNotExist:
        pass
    try:
        if provider.service_provider.enable_following_attribute_policy:
            if provider.service_provider.attribute_policy:
                return provider.service_provider.attribute_policy
    except:
        pass
    try:
        return AttributePolicy.objects.get(name='Default', enabled=True)
    except AttributePolicy.DoesNotExist:
        pass
    return None

# assure signals are loaded
from . import signals
