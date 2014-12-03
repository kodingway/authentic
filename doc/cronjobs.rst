.. _cronjobs:


Cronjobs and cleaning
=====================

The following cronjob must be run to clean deleted accounts and temporary objects::

   5 0 * * * athentic2-ctl cleanup

It's made to run every day at 00:05.
