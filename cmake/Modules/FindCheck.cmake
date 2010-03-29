# - Try to find Check
# Once done this will define
#
#  CHECK_FOUND - system has Check
#  CHECK_INCLUDE_DIRS - the Check include directory
#  CHECK_LIBRARIES - Link these to use Check
#  CHECK_DEFINITIONS - Compiler switches required for using Check
#
#  Copyright (c) 2010 Andreas Schneider <mail@cynapses.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (CHECK_LIBRARIES AND CHECK_INCLUDE_DIRS)
  # in cache already
  set(CHECK_FOUND TRUE)
else (CHECK_LIBRARIES AND CHECK_INCLUDE_DIRS)
  find_package(PkgConfig)
  if (PKG_CONFIG_FOUND)
    pkg_check_modules(_CHECK check)
  endif (PKG_CONFIG_FOUND)

  find_path(CHECK_INCLUDE_DIR
    NAMES
      check.h
    PATHS
      ${_CHECK_INCLUDEDIR}
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      /usr/lib/sfw/include
  )

  # check_pic is a workaround for ubuntu's check bug which does not compile
  # check as a shared library with -fPIC.
  # see https://bugs.launchpad.net/ubuntu/+source/check/+bug/125781
  find_library(CHECK_LIBRARY
    NAMES
      check_pic check
    PATHS
      ${_CHECK_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      /usr/sfw/lib/64
      /usr/sfw/lib
  )

  set(CHECK_INCLUDE_DIRS
    ${CHECK_INCLUDE_DIR}
  )

  if (CHECK_LIBRARY)
    set(CHECK_LIBRARIES
        ${CHECK_LIBRARIES}
        ${CHECK_LIBRARY}
    )
  endif (CHECK_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Check DEFAULT_MSG CHECK_LIBRARIES CHECK_INCLUDE_DIRS)

  # show the CHECK_INCLUDE_DIRS and CHECK_LIBRARIES variables only in the advanced view
  mark_as_advanced(CHECK_INCLUDE_DIRS CHECK_LIBRARIES)

endif (CHECK_LIBRARIES AND CHECK_INCLUDE_DIRS)

