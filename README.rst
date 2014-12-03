=======================================
Authentic 2 - Versatile Identity Server
=======================================

Authentic 2 is a versatile identity management server aiming to address a
broad range of needs, from simple to complex setups; it has support for many
protocols and can bridge between them.

Authentic 2 supports many protocols and standards, including SAML2, CAS,
OpenID, LDAP, X509 and OAUTH2.

Authentic 2 is under the GNU AGPL version 3 licence.

It has support for SAMLv2 thanks to `Lasso <http://lasso.entrouvert.org>`_,
a free (GNU GPL) implementation of the Liberty Alliance and OASIS
specifications of SAML2.

Authentic 2 requires Python 2.7 et Django 1.5.

Full documentation available on http://authentic2.readthedocs.org/en/stable/.

Features
--------

* SAML 2.0 Identity and service provider
* OpenID 1.0 and 2.0 identity provider
* Server CAS 1.0 and 2.0 using a plugin
* Standards authentication mechanisms:

    * Login/password through internal directory or LDAP
    * X509 certificate over SSL/TLS

* Protocol proxying, for instance between OpenID and SAML
* Support of LDAP v2 and v3 directories
* Support of the PAM backend
* One-time password (OATH and Google-Authenticator) using a plugin
* Identity attribute management
* Plugin system


Installation
============

First of all, you can boot Authentic vwithout root
privileges  like this:

# Initialize a virtualenv::

    virtualenv authentic
    source ./authentic/bin/activate
    cd authentic

# Install Authentic::

    pip install authentic2

# Initialize the database migrations::

    authentic2-ctl syncdb --migrate

# Run the HTTP test server::

    authentic2-ctl runserver


Support
=======

Authentic's developpers and users hangs on the mailing list
authentic@listes.entrouvert.com
See archives or register at http://listes.entrouvert.com/info/authentic.

You can "open":http://dev.entrouvert.org/projects/authentic/issues/new bug
reports or feature request on this site.

Entr'ouvert also provides a commercial support. For information, see
http://www.entrouvert.com.


Copyright
=========

Authentic is copyrighted by Entr'ouvert and is licensed through the GNU Affero
General Public Licence, version 3 or later. A copy of the whole license text
is available in the COPYING file.

The OpenID IdP originates in the project django_openid_provider by Roman
Barczy¿ski, which is under the Apache 2.0 licence. This imply that you must
distribute authentic2 under the AGPL3 licence when distributing this part of
the project which is the only AGPL licence version compatible with the
Apache 2.0 licence.
