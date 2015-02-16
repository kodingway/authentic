#!/bin/sh

set -e

pip install --upgrade pip
pip install --upgrade pylint==1.1.0
pip install --upgrade tox
(pylint -f parseable --rcfile /var/lib/jenkins/pylint.django.rc authentic2/ | tee pylint.out) || /bin/true
tox
