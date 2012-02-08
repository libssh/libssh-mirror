# - Try to find CMockery
# Once done this will define
#
#  CMOCKERY_ROOT_DIR - Set this variable to the root installation of CMockery
#
# Read-Only variables:
#  CMOCKERY_FOUND - system has CMockery
#  CMOCKERY_INCLUDE_DIR - the CMockery include directory
#  CMOCKERY_LIBRARIES - Link these to use CMockery
#  CMOCKERY_DEFINITIONS - Compiler switches required for using CMockery
#
#=============================================================================
#  Copyright (c) 2011-2012 Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

set(_OPENSSL_ROOT_PATHS
    "C:/OpenSSL/"
    $ENV{PROGRAMFILES}/cmockery/include
)

find_path(OPENSSL_ROOT_DIR
    NAMES
        include/google/cmockery.h
    PATHS
        ${_OPENSSL_ROOT_PATHS}
)
mark_as_advanced(OPENSSL_ROOT_DIR)

find_path(CMOCKERY_INCLUDE_DIR
    NAMES
        google/cmockery.h
    PATHS
        ${CMOCKERY_ROOT_DIR}/include
)

find_library(CMOCKERY_LIBRARY
    NAMES
        cmockery
    PATHS
        ${CMOCKERY_ROOT_DIR}/include
)

if (CMOCKERY_LIBRARY)
  set(CMOCKERY_LIBRARIES
      ${CMOCKERY_LIBRARIES}
      ${CMOCKERY_LIBRARY}
  )
endif (CMOCKERY_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CMockery DEFAULT_MSG CMOCKERY_LIBRARIES CMOCKERY_INCLUDE_DIR)

# show the CMOCKERY_INCLUDE_DIR and CMOCKERY_LIBRARIES variables only in the advanced view
mark_as_advanced(CMOCKERY_INCLUDE_DIR CMOCKERY_LIBRARIES)
