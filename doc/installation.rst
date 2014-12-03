.. _installation:

=====================================
Installation and quickstart tutorials
=====================================

You'll find here how to start and configure very quickly Authentic 2 for its
main features. You just need Python 2.7 and Django 1.5.

First of all, you can boot Authentic vwithout root
privileges  like this:

1. Initialize a virtualenv::

    virtualenv authentic
    source ./authentic/bin/activate
    cd authentic

2. Install Authentic::

    pip install authentic2

3. Initialize the database migrations::

    authentic2-ctl syncdb --migrate

4. Run the HTTP test server::

    authentic2-ctl runserver

Quickstart guides and installation guidelines
---------------------------------------------

.. toctree::
    :maxdepth: 1


    installation_modes
    change_db
    upgrading
    deployment

Quickstarts
___________

.. toctree::
    :maxdepth: 1

    quick_oauth2_idp
    quick_saml2_idp
    quick_saml2_sp
    quick_cas_idp 
    quick_ldap_backend
    quick_pam
