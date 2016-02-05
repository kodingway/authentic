#!/bin/sh

set -e

./getlasso.sh
# SNI support for Debian
pip install --upgrade pyOpenSSL ndg-httpsclient pyasn1
pip install --upgrade pip
pip install --upgrade pylint==1.4.0 astroid==1.3.2
pip install --upgrade tox
(pylint -f parseable --rcfile /var/lib/jenkins/pylint.django.rc src/authentic2/ | tee pylint.out) || /bin/true
tox -r
./merge-junit-results.py rbac-django17.xml django17.xml  >junit.xml
./merge-coverage.py -o coverage.xml *coverage.xml
