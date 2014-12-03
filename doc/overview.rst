.. _overview:

========
Overview
========

Authentic 2 is a versatile identity management server aiming to address a
broad range of needs, from simple to complex setups; it has support for many
protocols and can bridge between them.

Authentic 2 supports many protocols and standards, including SAML2, CAS, OpenID,
LDAP, X509 and OAUTH2.

Authentic 2 is under the GNU AGPL version 3 licence.

It has support for SAMLv2 thanks to `Lasso <http://lasso.entrouvert.org>`_,
a free (GNU GPL) implementation of the Liberty Alliance and OASIS
specifications of SAML2.

Authentic 2 requires Python 2.7 et Django 1.5.

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


Source and issue tracker
------------------------

You can find on the project site authentic.entrouvert.org mainly the issue
tracker.

You can find there a viewer of the git repository or clone it::

    git clone http://repos.entrouvert.org/authentic.git

Support
-------
Authentic's developpers and users hangs on the mailing list authentic@listes.entrouvert.com.
See archives or register at http://listes.entrouvert.com/info/authentic.

You can open reports or feature request on http://authentic.entrouvert.org.

Entr'ouvert also provides a commercial support. For information, visit http://www.entrouvert.com.
