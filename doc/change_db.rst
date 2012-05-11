.. _change_db:

===============================
Specifying a different database
===============================

This is done by modifying the DATABASES dictionary in your local_settings.py
file (create it in Authentic project directory); for example::

 DATABASES['default'] = {
   'ENGINE': 'django.db.backends.postgresql',
   'NAME': 'authentic',
   'USER': 'admindb',
   'PASSWORD': 'foobar',
   'HOST': 'db.example.com',
   'PORT': '', # empty string means default value
 }

You should refer to the Django documentation on databases settings at
http://docs.djangoproject.com/en/dev/ref/settings/#databases for all
the details.
