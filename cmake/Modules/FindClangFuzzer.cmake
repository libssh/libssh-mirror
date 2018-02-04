# - Try to find Fuzzer
# Once done this will define
#
#  CLANG_FUZZER_FOUND - system has Fuzzer
#  CLANG_FUZZER_LIBRARY - Link these to use Fuzzer
#
#=============================================================================
#  Copyright (c) 2018 Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

find_package(Clang REQUIRED CONFIG)

find_library(CLANG_FUZZER_LIBRARY
    NAMES
        Fuzzer
    HINTS
        ${LLVM_LIBRARY_DIR}/clang/${LLVM_PACKAGE_VERSION}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Fuzzer DEFAULT_MSG CLANG_FUZZER_LIBRARY)

# show the CLANG_FUZZER_LIBRARY variables only in the advanced view
mark_as_advanced(CLANG_FUZZER_LIBRARY)
