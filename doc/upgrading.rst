.. _upgrading:

=========
Upgrading
=========

Update using pip::

    pip install -U authentic2

Authentic store all its data in a relational database as specified in its
settings.py or local_settings.py file. So in order to upgrade to a new version
of authentic you have to update your database schema using the
migration command — you will need to have installed the dependency django-south,
see the beginning of this README file.::

    authentic2-ctl syncdb --migrate
