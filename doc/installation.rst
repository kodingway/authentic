.. _installation:

============
Installation
============

Authentic 2 installation script handles all the dependencies, except Lasso,
relying on the Setuptools and the pypi repository.

To run Authentic 2 you need to install Lasso >=2.3.6. You can obtain Lasso
from:

- From sources: http://lasso.entrouvert.org/download
- Debian based distribution: http://deb.entrouvert.org/

The other Authentic 2 dependencies are:

- django >= 1.3
- django-profiles >= 0.2
- south >= 0.7.3
- django-authopenid >= 0.9.6
- django-debug-toolbar >= 0.9.0

Their management depends on how you install Authentic 2:

- You can :ref:`install-pypi-ref`
- You can :ref:`obtain-pypi-ref`
- You can :ref:`obtain-git-ref`

Lasso installation mock-up
--------------------------

Please see the Lasso website for installation details. This is a quick
installation example.

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

or easy_install::

   easy_install authentic2

You can now run Authentic from the installation directory, e.g.::

   python /usr/local/lib/python2.6/site-packages/authentic2-x.y.z-py2.6.egg/authentic2/manage.py syncdb --migrate
   python /usr/local/lib/python2.6/site-packages/authentic2-x.y.z-py2.6.egg/authentic2/manage.py runserver

You should see the following output::

  Validating models...
  0 errors found

  Django version 1.4, using settings 'authentic.settings'
  Development server is running at http://127.0.0.1:8000/
  Quit the server with CONTROL-C.

  You can access the running application on http://127.0.0.1:8000/

.. _obtain-pypi-ref:

Obtain the last package archive from pypi
-----------------------------------------

Download the archive on http://pypi.python.org/pypi/authentic2/.

Then, you can install it directly from the archive using pip::

   pip install authentic2-x.z.y.tar.gz

or easy_install::

   easy_install authentic2-x.z.y.tar.gz

You can now run Authentic from the installation directory, e.g.::

   python /usr/local/lib/python2.6/site-packages/authentic2-x.y.z-py2.6.egg/authentic2/manage.py syncdb --migrate
   python /usr/local/lib/python2.6/site-packages/authentic2-x.y.z-py2.6.egg/authentic2/manage.py runserver

You should see the following output::

  Validating models...
  0 errors found

  Django version 1.4, using settings 'authentic.settings'
  Development server is running at http://127.0.0.1:8000/
  Quit the server with CONTROL-C.

  You can access the running application on http://127.0.0.1:8000/

You may not want to install the authentic2 package or you may want to manage the dependencies
_____________________________________________________________________________________________

Then, extract the archive::

   tar xzvf authentic2-x.z.y.tar.gz
   cd authentic2-x.z.y

You can now install the dependencies by hands or use pypi to install them as
follows, either::

   pip install django django-profiles south django-authopenid django-debug-toolbar

or using the dependencies version requirements::

   python setup.py egg_info
   pip install -r authentic2.egg-info/requires.txt

Then run Authentic from the extracted directory::

   python authentic2/manage.py syncdb --migrate
   python authentic2/manage.py runserver

You should see the following output::

  Validating models...
  0 errors found

  Django version 1.4, using settings 'authentic.settings'
  Development server is running at http://127.0.0.1:8000/
  Quit the server with CONTROL-C.

  You can access the running application on http://127.0.0.1:8000/

.. _obtain-git-ref:

Obtain the last sources from the Git repository
-----------------------------------------------

Clone the repository::

   git clone http://repos.entrouvert.org/authentic.git

Then, you can install it directly using pip::

   pip install ./authentic

or easy_install::

   easy_install ./authentic

You can now run Authentic from the installation directory, e.g.::

   python /usr/local/lib/python2.6/site-packages/authentic2-x.y.z-py2.6.egg/authentic2/manage.py syncdb --migrate
   python /usr/local/lib/python2.6/site-packages/authentic2-x.y.z-py2.6.egg/authentic2/manage.py runserver

You should see the following output::

  Validating models...
  0 errors found

  Django version 1.4, using settings 'authentic.settings'
  Development server is running at http://127.0.0.1:8000/
  Quit the server with CONTROL-C.

  You can access the running application on http://127.0.0.1:8000/

You may not want to install the authentic2 package or you may want to manage the dependencies
_____________________________________________________________________________________________

Then, extract the archive::

   cd authentic

You can now install the dependencies by hands or use pypi to install them as
follows, either::

   pip install django django-profiles south django-authopenid django-debug-toolbar

or using the dependencies version requirements::

   python setup.py egg_info
   pip install -r authentic2.egg-info/requires.txt

Then run Authentic::

   python authentic2/manage.py syncdb --migrate
   python authentic2/manage.py runserver

You should see the following output::

  Validating models...
  0 errors found

  Django version 1.4, using settings 'authentic.settings'
  Development server is running at http://127.0.0.1:8000/
  Quit the server with CONTROL-C.

  You can access the running application on http://127.0.0.1:8000/
