.. _quick_saml2_sp:

=====================================================
Quickstart a connection with a SAML2 Service Provider
=====================================================

1. Get the Identity Provider SAML2 metadata file

::

    http[s]://your.domain.com/idp/saml2/metadata

2. Configure your service provider with it.

3. Go to the providers admin panel on

::

    http[s]://admin/saml/libertyprovider/add/

There create a new provider using the service provider metadata and enable it
as a service provider.
