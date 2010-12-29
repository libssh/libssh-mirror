# - Try to find CMockery
# Once done this will define
#
#  CMOCKERY_FOUND - system has CMockery
#  CMOCKERY_INCLUDE_DIRS - the CMockery include directory
#  CMOCKERY_LIBRARIES - Link these to use CMockery
#  CMOCKERY_DEFINITIONS - Compiler switches required for using CMockery
#
#  Copyright (c) 2010 Andreas Schneider <asn@cryptomilk.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (CMOCKERY_LIBRARIES AND CMOCKERY_INCLUDE_DIRS)
  # in cache already
  set(CMOCKERY_FOUND TRUE)
else (CMOCKERY_LIBRARIES AND CMOCKERY_INCLUDE_DIRS)

  find_path(CMOCKERY_INCLUDE_DIR
    NAMES
      google/cmockery.h
    PATHS
      ${_CMOCKERY_DIR}/include
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      $ENV{PROGRAMFILES}/cmockery/include
  )

  find_library(CMOCKERY_LIBRARY
    NAMES
      cmockery
    PATHS
      ${_CMOCKERY_DIR}/lib
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      $ENV{PROGRAMFILES}/cmockery/lib
  )

  set(CMOCKERY_INCLUDE_DIRS
    ${CMOCKERY_INCLUDE_DIR}
  )

  if (CMOCKERY_LIBRARY)
    set(CMOCKERY_LIBRARIES
        ${CMOCKERY_LIBRARIES}
        ${CMOCKERY_LIBRARY}
    )
  endif (CMOCKERY_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(CMockery DEFAULT_MSG CMOCKERY_LIBRARIES CMOCKERY_INCLUDE_DIRS)

  # show the CMOCKERY_INCLUDE_DIRS and CMOCKERY_LIBRARIES variables only in the advanced view
  mark_as_advanced(CMOCKERY_INCLUDE_DIRS CMOCKERY_LIBRARIES)

endif (CMOCKERY_LIBRARIES AND CMOCKERY_INCLUDE_DIRS)
