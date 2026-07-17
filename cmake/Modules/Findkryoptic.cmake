# - Try to find kryoptic
# Once done this will define
#
#  KRYOPTIC_FOUND - system has kryoptic
#  KRYOPTIC_LIBRARIES - Link these to use kryoptic
#
#=============================================================================
#  Copyright (c) 2026 Pavol Žáčik <pzacik@redhat.com>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#


find_library(KRYOPTIC_LIBRARY
    NAMES
        kryoptic_pkcs11
    PATH_SUFFIXES
        pkcs11
)

if (KRYOPTIC_LIBRARY)
    set(KRYOPTIC_LIBRARIES
        ${KRYOPTIC_LIBRARIES}
        ${KRYOPTIC_LIBRARY}
    )
endif (KRYOPTIC_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(kryoptic DEFAULT_MSG KRYOPTIC_LIBRARIES)

# show the KRYOPTIC_LIBRARIES variable only in the advanced view
mark_as_advanced(KRYOPTIC_LIBRARIES)
