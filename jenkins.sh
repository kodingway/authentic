#!/bin/sh

set -e

(pylint -f parseable --rcfile /var/lib/jenkins/pylint.django.rc authentic2/ | tee pylint.out) || /bin/true
tox
