#!/bin/sh
PROJECT=authentic2
CTL=${PROJECT}-ctl
VENV=${PROJECT}-venv

if [ "$VIRTUAL_ENV" = "" ]; then
	if which mkvirtualenv >/dev/null 2>&1; then
		workon $PROJECT || (mkvirtualenv $PROJECT; workon $PROJECT)
	else 
		if [ ! -d $VENV ]; then
			virtualenv --system-site-packages $VENV 2>/dev/null || virtualenv $VENV
		fi
		. ./$VENV/bin/activate
	fi
fi
easy_install -U pip distribute
pip install -U django>1.5.0,<1.6
pip install -U -r requirements.txt
if [ ! -f $PROJECT.db ]; then
	./$CTL syncdb --all --noinput
	./$CTL migrate --fake
	./load-base-data.sh
fi
./$CTL runserver
