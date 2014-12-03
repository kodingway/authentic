.. _installation_modes:

==================
Installation modes
==================

The current version of Authentic 2 works with Python 2.7 and Django 1.5.

Authentic 2 python installation script handles all the dependencies,
except Lasso, relying on the Setuptools and the pypi repository.

To run Authentic 2 with SAML2 features, you need to install lasso >= 2.3.6,
see :ref:`install-lasso-ref`.

The other Authentic 2 dependencies are:

- Django<1.6
- south>=0.8.4
- requests
- django-model-utils
- django-registration>=1
- django-debug-toolbar>=1.2,<1.3
- --allow-external django-admin-tools
- --allow-unverified django-admin-tools
- django-admin-tools>=0.5.1
- dnspython
- django-select2
- django-tables2
- gadjo
- django-import-export
- django-sekizai

Install Authentic 2:

- :ref:`install-pypi-ref`
- :ref:`obtain-pypi-ref`
- :ref:`obtain-git-ref`

.. _install-lasso-ref:

Lasso installation
------------------

Lasso is available in the linux debian destribution repositories. If you are
installing Authentic 2 on debian, just execute ::

   apt-get install python-lasso

You'll find more updated packages on http://deb.entrouvert.org/.

We also provide rpm packages for redhat, see https://dev.entrouvert.org/redhat/README.

You can also install lasso from sources  http://lasso.entrouvert.org/download

See the `Lasso website <http://lasso.entrouvert.org>`_ for installation details.
This is a quick installation example.

Install the following Lasso dependencies:

- autoconf
- automake
- autotools-dev
- libtool
- gtk-doc-tools
- zlib1g-dev
- libglib2.0-dev
- openssl-dev
- libxml2-dev
- libxmlsec1-dev
- python2.6-dev
- python-setuptools

Obtain Lasso::

  $wget https://dev.entrouvert.org/lasso/lasso-2.3.6.tar.gz
  $tar xzvf lasso-2.3.6.tar.gz
  $cd lasso-2.3.6
  $./autogen.sh

Be sure that the Python bindings is selected as follows::

    =============
    Configuration
    =============

    Main
    ----

    Compiler:                gcc
    CFLAGS:
    Install prefix:          /usr/local
    Debugging:               no
    Experimental ID-WSF:     no

    Optionals builds
    ----------------

    Available languages:    java(4.6.1) python(2.7) perl(5.12.4)

    Java binding:           yes
    Perl binding:           yes
    PHP 5 binding:          no
    Python binding:         yes

    C API references:       yes
    Tests suite:            no


    Now type 'make install' to install lasso.

As indicated, build and install::

  $make install
  $ldconfig

Set the lasso python binding in you python path, e.g.::

  $export PYTHONPATH="$PYTHONPATH:/usr/local/lib/python2.6/site-packages"

Test trying to import Lasso::

  $python
  >>> import lasso

.. _install-pypi-ref:

Install Authentic directly from pypi
------------------------------------

Using pip::

   pip install authentic2

You can now run Authentic from the installation directory::

   ./authentic2-ctl syncdb --migrate
   ./authentic2-ctl runserver

You should see the following output::

  Validating models...
  0 errors found

  Django version 1.5, using settings 'authentic.settings'
  Development server is running at http://127.0.0.1:8000/
  Quit the server with CONTROL-C.

  You can access the running application on http://127.0.0.1:8000/

.. _obtain-pypi-ref:

Obtain the last package archive from pypi
-----------------------------------------

Download the archive on http://pypi.python.org/pypi/authentic2/.

Then, you can install it directly from the archive using pip::

   pip install authentic2-x.z.y.tar.gz

You can now run Authentic from the installation directory, e.g.::

   ./authentic2-ctl syncdb --migrate
   ./authentic2-ctl runserver

You should see the following output::

  Validating models...
  0 errors found

  Django version 1.5, using settings 'authentic.settings'
  Development server is running at http://127.0.0.1:8000/
  Quit the server with CONTROL-C.

  You can access the running application on http://127.0.0.1:8000/

.. _obtain-git-ref:

Obtain the last sources from the Git repository
-----------------------------------------------

Clone the repository::

   git clone http://repos.entrouvert.org/authentic.git

Then, you can install it directly using pip::

   cd authentic
   pip install -e .

You can now run Authentic from the installation directory, e.g.::

   ./authentic2-ctl syncdb --migrate
   ./authentic2-ctl runserver

You should see the following output::

  Validating models...
  0 errors found

  Django version 1.5, using settings 'authentic.settings'
  Development server is running at http://127.0.0.1:8000/
  Quit the server with CONTROL-C.

  You can access the running application on http://127.0.0.1:8000/
