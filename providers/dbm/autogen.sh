#!/bin/sh

rm -rf autom4te-2.53.cache
autoheader-2.53
autoconf-2.53
touch stamp-h.in
