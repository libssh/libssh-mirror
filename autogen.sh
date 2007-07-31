#!/bin/sh -e

aclocal
libtoolize --force --copy
autoheader
autoconf
automake --add-missing --copy --gnu
./configure $@
