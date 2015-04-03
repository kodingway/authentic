.. _sync-metadata_script:

===========================================================================================================
How to create/import and delete in bulk SAML2 identity and service providers with the sync-metadata script?
===========================================================================================================

This section explains hot to use the script sync-metadata.

Presentation
============

This script allows to create/import and deleted in bulk SAML2 identity and
service providers using standard SAML2 metadata files containing entity
descriptors.

An example of such a file used in production is the global metadata file of
the identity federation of French universities that can be found at http://...

Use the following command::

    path_to_project/authentic2$ python manage.py sync-metadata file_name [options]

Configuration of attributes
===========================

If a service provider has AttributeConsumingService nodes in its
SPSSODescriptor then we create an attribute declaration for each declared
attribute. If the attribute is optional, the attribute declaration is created
disabled.

Currently it only supports the LDAP and the LDAP attribute profile of SAML,
i.e. SAML attribute names must be LDAP attributes oid, the NameFormat must be
URI, and an LDAP server must declared so that LDAP attributes can be resolved.
Authentic2 contains a databases of the more common LDAP schemas to help the
resolution of attributes OIDs.

Example of an AttributeConsumingService node::

    <md:AttributeConsumingService index="0">
         <md:ServiceName
               xml:lang="fr">Université Paris 1 - cours en ligne</md:ServiceName>

        <md:ServiceDescription xml:lang="fr">Cours en ligne de l'université
            Paris 1 Panthéon - Sorbonne (LMS Moodle)
        </md:ServiceDescription>


        <md:RequestedAttribute FriendlyName="sn" Name="urn:oid:2.5.4.4"
           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
           isRequired="true">

        </md:RequestedAttribute>

        <md:RequestedAttribute FriendlyName="mail"
           Name="urn:oid:0.9.2342.19200300.100.1.3"
           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
           isRequired="true">

        </md:RequestedAttribute>

        <md:RequestedAttribute FriendlyName="displayName"
           Name="urn:oid:2.16.840.1.113730.3.1.241"
           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
           isRequired="true">

        </md:RequestedAttribute>

        <md:RequestedAttribute FriendlyName="eduPersonPrincipalName"
           Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
           isRequired="true">

        </md:RequestedAttribute>

        <md:RequestedAttribute FriendlyName="eduPersonAffiliation"
           Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
           isRequired="true">

        </md:RequestedAttribute>

        <md:RequestedAttribute FriendlyName="givenName" Name="urn:oid:2.5.4.42"
           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
           isRequired="true">

        </md:RequestedAttribute>

        <md:RequestedAttribute FriendlyName="cn" Name="urn:oid:2.5.4.3"
           NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
           isRequired="true">

        </md:RequestedAttribute>

    </md:AttributeConsumingService>

If you do not want the attribute declarations to be automatically created pass
the option `--dont-load-attribute-consuming-service` to the `sync-metadata` command.

Options
=======

* idp

    Load only identity providers of the metadata file.

* sp

    Load only service providers of the metadata file.

* source

    Used to tag all imported providers with a label. This option is used to
    metadata reloading and deletion in bulk.

    Reloading a metadata file, when a provider with same entity is found, it is
    updated. If a provider in the metadata file does not exist it is created.
    If a provider exists in the system but not in the metadata file, it is
    removed.

    **For reloading, a source can only be associated with a unique metadata
    file. This is due to the fact that all providers of a source not found in
    the metadata file are removed.** ::

      path_to_project/authentic2$ python manage.py sync-metadata file_name --source=french_federation

* sp-policy

    To configure the SAML2 parameters of service providers imported with the
    script, a policy of type SPOptionsIdPPolicy must be created in the
    the administration interface.
    Either it is a global policy 'Default' or 'All' or it is a regular policy.
    If it is a regular policy, the policy name can be specified in parameter
    of the script with this option.
    The policy is then associated to all service providers created.

::

    path_to_project/authentic2$ python manage.py sync-metadata file_name --sp-policy=sp_policy_name

* idp-policy

    To configure the SAML2 parameters of identity providers imported with the
    script, a policy of type IdPOptionsSPPolicy must be created in the
    the administration interface.
    Either it is a global policy 'Default' or 'All' or it is a regular policy.
    If it is a regular policy, the policy name can be specified in parameter
    of the script with this option.
    The policy is then associated to all service providers created.

    ::

      path_to_project/authentic2$ python manage.py sync-metadata file_name --idp-policy=idp_policy_name

* delete

    With no options, all providers are deleted.

    With the source option, only providers with the source name given are deleted.

    **This option can not be combined with options idp and sp.**

* ignore-errors

    If loading of one EntityDescriptor fails, continue loading

* reset-atributes

    When loading shibboleth attribute filter policies, start by removing all
    existing SAML attributes for each provider, beware that it will delete any
    customization of the attribute policy for each service provider.

* dont-load-attribute-consuming-service

    Prevent loading of the attribute policy from AttributeConsumingService nodes
    in the metadata file.

* shibboleth-attribute-filter-policy

    Path to a file containing an Attribute Filter Policy for the
    Shibboleth IdP, that will be used to configure SAML attributes for
    each provider. The following schema is supported::

        <AttributeFilterPolicy id="<whatever>">
            <PolicyRequirementRule xsi:type="basic:AttributeRequesterString" value="<entityID>" >
            [
              <AttributeRule attributeID="<attribute-name>">
                    <PermitValueRule xsi:type="basic:ANY"/>
              </AttributeRule>
            ]*
        </AttributeFilterPolicy>

    Any other kind of attribute filter policy is unsupported.
