.. _production:

================================
Deploy Authentic 2 in production
================================

DEBUG Mode by default, static files and the Django debug toolbar dependency ?
-----------------------------------------------------------------------------

By default, Authentic 2 is in the DEBUG mode. We made this default choice
because most of the Authentic 2's users will begin with Authentic 2 using
the Django development server (runserver command) and we want to avoid them
a bad first impression because static files would not be served. As a matter
of fact, static files are served by the Django development server only when
the project is run in the DEBUG mode.

In the DEBUG mode, the Django debug toolbar is used what adds a dependency.

In production, the Django development server should not be used to serve
Authentic 2 and a dedicated server should also be used to serve the static
files.

Set Authentic into the no DEBUG Mode
------------------------------------

It is enough to edit authentic2/settings.py and set::

   DEBUG = False

From then on the django-debug-toolbar package is not necessary anymore.

Use dedicated HTTP servers and serve static files
-------------------------------------------------

The best is to use a server dedicated to serve the Django applications and a
different server to serve the static files.

You could for instance use apache with mod_wsgi to serve Authentic 2. You will
find configuration file examples in the debian directory of the Authentic 2
sources.

Then you may want to use nginx to serve the static files.

First you need to collect the Authentic 2 static files. The static files are
collected using the collectstatic command that is configured in the
settings.py.

By default, running collectstatic will create a static directory in the parent
directory of the authentic2 directory::

  $python authentic2/manage.py collectstatic

That static directory will contain all the static files of Authentic 2.

If you want to change the path of the static directory you can edit
STATIC_ROOT of the settings file.

See https://docs.djangoproject.com/en/dev/ref/contrib/staticfiles/ for more
information about collectstatic.
