#!/bin/sh

rm -rf autom4te-2.53.cache
autoheader-2.53
autoconf-2.53
touch stamp-h.in

for x in providers/*; do
	if [ -e $x/autogen.sh ]; then
		echo Generating Config files in $x
		(cd $x; ./autogen.sh $*)
	fi
done
