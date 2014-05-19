#!/bin/sh

pip install --upgrade pip
pip install --upgrade pylint==1.1.0
pip install --upgrade -v -r requirements.txt
pip install --upgrade django-authopenid
export SECRET_KEY='coin'
./authentic2-ctl syncdb --noinput --all
./authentic2-ctl migrate --fake
./authentic2-ctl validate
(pylint -f parseable --rcfile /var/lib/jenkins/pylint.django.rc authentic2/ | tee pylint.out) || /bin/true
