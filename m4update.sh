#!/bin/sh
for x in providers/*; do
    if [ -e $x/m4/apache.m4 ]; then
	cp -v m4/apache.m4 $x/m4/apache.m4
    fi
done
