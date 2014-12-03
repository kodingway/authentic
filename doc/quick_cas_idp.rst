.. _quick_cas_idp:

==================================
Quickstart a CAS Identity Provider
==================================

1. Activate CAS IdP support in your local_settings.py::

 IDP_CAS = True

2. Then create the database table to hold CAS service tickets::

 authentic2-ctl syncdb --all
 authentic2-ctl migrate --fake

2. Also configure authentic2 to authenticate against your LDAP directory (see
   above) if your want your user attributes to be accessible from your service,
   if it is not necessary you can use the normal relational database storage
   for you users.

3. Finally configure your service to point to the CAS endpoint at::

 http[s]://your.domain.com/idp/cas/
