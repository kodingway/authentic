#!/bin/sh
BASE=`dirname $0`
PROJECT=authentic2
CTL=$BASE/${PROJECT}-ctl
VENV=$BASE/${PROJECT}-venv

if [ ! -d $VENV ]; then
	$BASE/start.sh
else
	. $VENV/bin/activate
	$CTL "${@:-runserver}"
fi
