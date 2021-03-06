#!/bin/bash

set -e

./getlasso.sh
# SNI support for Debian
pip install --upgrade pyOpenSSL ndg-httpsclient pyasn1
pip install --upgrade pip\>9
pip install --upgrade pylint pylint-django
pip install --upgrade tox
pip install -U 'virtualenv<14'
rm -f coverage*.xml junit*.xml
if [[ `date +%H%M` < 630 ]]; then
	# run full tests (with migrations) at night
	tox -r -e 'coverage-dj18-{authentic,rbac}-{pg,sqlite}'
else
	tox -r -e 'fast-coverage-dj18-{authentic,rbac}-{pg,sqlite}'
fi
(pylint -f parseable --rcfile /var/lib/jenkins/pylint.django.rc src/authentic2/ | tee pylint.out) || /bin/true
./merge-junit-results.py junit-*coverage-dj18-authentic-pg.xml junit-*coverage-dj18-rbac-pg.xml > junit.xml
./merge-coverage.py -o coverage.xml coverage-*.xml
