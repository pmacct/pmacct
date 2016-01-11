#!/usr/bin/env bash
#
#

BASEDIR=$(dirname $0)

sleep 1
touch $BASEDIR/../aclocal.m4
sleep 1
touch $BASEDIR/../configure
sleep 1
touch `find $BASEDIR/.. -name Makefile.in -print`
