#!/bin/sh

. /etc/authentic2/authentic.conf

python /usr/lib/authentic2/manage.py syncdb --all --noinput
python /usr/lib/authentic2/manage.py migrate --fake --noinput

