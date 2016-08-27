#!/bin/sh

set -e

./getlasso.sh
# SNI support for Debian
pip install --upgrade pyOpenSSL ndg-httpsclient pyasn1
pip install --upgrade pip
pip install --upgrade pylint pylint-django
pip install --upgrade tox
pip install -U 'virtualenv<14'
rm -f coverage*.xml
tox -r -e 'fast-coverage-{dj17,dj18}-{authentic,rbac}-{pg,sqlite}'
(pylint -f parseable --rcfile /var/lib/jenkins/pylint.django.rc src/authentic2/ | tee pylint.out) || /bin/true
./merge-junit-results.py rbac-django17.xml django17.xml  >junit.xml
./merge-coverage.py -o coverage.xml coverage-*.xml
