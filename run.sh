#!/bin/sh
PROJECT=authentic2
CTL=${PROJECT}-ctl
VENV=${PROJECT}-venv

if [ ! -d $VENV ]; then
	./start.sh
else
	. ./$VENV/bin/activate
	./$CTL "${@:-runserver}"
fi
