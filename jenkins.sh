#!/bin/sh

set -e

pip install --upgrade pip
pip install --upgrade pylint==1.4.0 astroid==1.3.2
pip install --upgrade tox
(pylint -f parseable --rcfile /var/lib/jenkins/pylint.django.rc src/ | tee pylint.out) || /bin/true
tox
