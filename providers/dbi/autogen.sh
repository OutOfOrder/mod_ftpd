#!/bin/sh

rm -rf autom4te-2.53.cache
if [ -z $AUTOCONF ]; then 
	AUTOCONF=autoconf-2.53
fi
if [ -z $AUTOHEADER ]; then
	AUTOHEADER=autoheader-2.53
fi
$AUTOHEADER
$AUTOCONF
touch stamp-h.in
