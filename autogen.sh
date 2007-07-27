#!/bin/sh -e

libtoolize --force --copy
aclocal
autoheader
autoconf
automake --add-missing --copy --gnu
