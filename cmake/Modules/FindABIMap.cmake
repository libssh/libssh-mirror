#
#  Copyright (c) 2018 Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

#.rst:
# FindABIMap
# ----------
#
# This file provides functions to generate the symbol version script. It uses
# the ``abimap`` tool to generate and update the linker script file. It can be
# installed by calling::
#
#   $ pip install abimap
#
# The ``function generate_map_file`` generates a symbol version script
# containing the provided symbols. It defines a custom command which sets
# ``target_name`` as its ``OUTPUT``.
#
# The experimental function ``extract_symbols()`` is provided as a simple
# parser to extract the symbols from C header files. It simply extracts symbols
# followed by an opening '``(``'. It is recommended to use a filter pattern to
# select the lines to be considered. It defines a custom command which sets
# ``target_name`` as its output.
#
# The helper function ``get_files_list()`` is provided to find files given a
# name pattern. It defines a custom command which sets ``target_name`` as its
# output.
#
# Functions provided
# ------------------
#
# ::
#
#   generate_map_file(target_name
#                     RELEASE_NAME_VERSION release_name
#                     SYMBOLS symbols_file
#                     [CURRENT_MAP cur_map]
#                     [FINAL]
#                     [BREAK_ABI]
#                     [COPY_TO output]
#                    )
#
# ``target_name``:
#   Required, expects the name of the file to receive the generated symbol
#   version script. It should be added as a dependency for the library. Use the
#   linker option ``--version-script filename`` to add the version information
#   to the symbols when building the library.
#
# ``RELEASE_NAME_VERSION``:
#   Required, expects a string containing the name and version information to be
#   added to the symbols in the format ``lib_name_1_2_3``.
#
# ``SYMBOLS``:
#   Required, expects a file containing the list of symbols to be added to the
#   symbol version script.
#
# ``CURRENT_MAP``:
#   Optional. If given, the new set of symbols will be checked against the
#   ones contained in the ``cur_map`` file and updated properly. If an
#   incompatible change is detected and ``BREAK_ABI`` is not defined, the build
#   will fail.
#
# ``FINAL``:
#   Optional. If given, will provide the ``--final`` option to ``abimap`` tool,
#   which will mark the modified release in the symbol version script with a
#   special comment, preventing later changes. This option should be set when
#   creating a library release and the resulting map file should be stored with
#   the source code.
#
# ``BREAK_ABI``:
#   Optional. If provided, will use ``abimap`` ``--allow-abi-break`` option, which
#   accepts incompatible changes to the set of symbols. This is necessary if any
#   previously existing symbol were removed.
#
# ``COPY_TO``:
#   Optional, expects a string containing the path to where the generated
#   map file will be copied.
#
# Example:
#
# .. code-block:: cmake
#
#   find_package(ABIMap)
#   generate_map_file("lib.map"
#                     RELEASE_NAME_VERSION "lib_1_0_0"
#                     SYMBOLS "symbol1;symbol2"
#                    )
#
# This example would result in the symbol version script to be created in
# ``${CMAKE_CURRENT_BINARY_DIR}/lib.map`` containing the provided symbols.
#
# ::
#
#   get_files_list(target_name
#                   DIRECTORIES dir1 [dir2 ...]
#                   FILES_PATTERNS exp1 [exp2 ...]
#                   [COPY_TO output]
#                  )
#
# ``target_name``:
#   Required, expects the name of the target to be created. A file named after
#   the string given in ``target_name`` will be created in
#   ``${CMAKE_CURRENT_BINARY_DIR}`` to receive the list of files found.
#
# ``DIRECTORIES``:
#   Required, expects a list of directories paths. Only absolute paths are
#   supported.
#
# ``FILES_PATTERN``:
#   Required, expects a list of matching expressions to find the files to be
#   considered.
#
# ``COPY_TO``:
#   Optional, expects a string containing the path to where the file containing
#   the list of files will be copied.
#
# This command searches the directories provided in ``DIRECTORIES`` for files
# matching any of the patterns provided in ``FILES_PATTERNS``. The obtained list
# is written to the path specified by ``output``.
#
# Example:
#
# .. code-block:: cmake
#
#   find_package(ABIMap)
#   get_files_list(target
#     DIRECTORIES "/include/mylib"
#     FILES_PATTERNS "*.h"
#     COPY_TO "my_list.txt"
#   )
#
# Consider that ``/include/mylib`` contains 3 files, ``h1.h``, ``h2.h``, and
# ``h3.hpp``
#
# Will result in a file ``my_list.txt`` containing::
#
#   ``h1.h;h2.h``
#
# ::
#
#   extract_symbols(target_name
#                   HEADERS_LIST_FILE headers_list
#                   [FILTER_PATTERN pattern]
#                   [COPY_TO output]
#                  )
#
# ``target_name``:
#   Required, expects the name of the target to be created. A file named after
#   the string given in ``target_name`` will be created in
#   ``${CMAKE_CURRENT_BINARY_DIR}`` to receive the list of symbols.
#
# ``HEADERS_LIST_FILE``:
#   Required, expects a path to a file containing the list of header files to be
#   parsed.
#
# ``FILTER_PATTERN``:
#   Optional, expects a string. Only the lines containing the filter pattern
#   will be considered.
#
# ``COPY_TO``:
#   Optional, expects a string containing the path to where the file containing
#   the found symbols will be copied.
#
# This command extracts the symbols from the files listed in
# ``headers_list`` and write them on the ``output`` file. If ``pattern``
# is provided, then only the lines containing the string given in ``pattern``
# will be considered. It is recommended to provide a ``FILTER_PATTERN`` to mark
# the lines containing exported function declaration, since this function is
# experimental and can return wrong symbols when parsing the header files.
#
# Example:
#
# .. code-block:: cmake
#
#   find_package(ABIMap)
#   extract_symbols("lib.symbols"
#     HEADERS_LIST_FILE "headers_list"
#     FILTER_PATTERN "API_FUNCTION"
#   )
#
# Where headers_list contains::
#
#   header1.h;header2.h
#
# Where ``header1.h`` contains::
#
#   API_FUNCTION int exported_func1(int a, int b);
#
# ``header2.h`` contains::
#
#   API_FUNCTION int exported_func2(int a);
#
#   int private_func2(int b);
#
# Will result in a file ``lib.symbols`` in ``${CMAKE_CURRENT_BINARY_DIR}`` containing::
#
#   ``exported_func1;exported_func2``
#

# Search for python which is required
find_package(PythonInterp REQUIRED)

# Search for abimap tool used to generate the map files
find_program(ABIMAP_EXECUTABLE NAMES abimap DOC "path to the abimap executable")
mark_as_advanced(ABIMAP_EXECUTABLE)

if (NOT ABIMAP_EXECUTABLE AND UNIX)
    message(STATUS "Could not find `abimap` in PATH."
                   " It can be found in PyPI as `abimap`"
                   " (try `pip install abimap`)")
else ()
    set(ABIMAP_FOUND TRUE)
endif ()

# Define helper scripts
set(_EXTRACT_SYMBOLS_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/ExtractSymbols.cmake)
set(_GENERATE_MAP_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/GenerateMap.cmake)
set(_GET_FILES_LIST_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/GetFilesList.cmake)

function(get_file_list _TARGET_NAME)

    set(one_value_arguments
      COPY_TO
    )

    set(multi_value_arguments
      DIRECTORIES
      FILES_PATTERNS
    )

    cmake_parse_arguments(_get_files_list
      ""
      "${one_value_arguments}"
      "${multi_value_arguments}"
      ${ARGN}
    )

    # The DIRS argument is required
    if (NOT DEFINED _get_files_list_DIRECTORIES)
        message(FATAL_ERROR "No directories paths provided. Provide a list of"
                            " directories paths containing header files."
         )
     endif()

    # The FILES_PATTERNS argument is required
    if (NOT DEFINED _get_files_list_FILES_PATTERNS)
        message(FATAL_ERROR "No matching expressions provided. Provide a list"
                            " of matching patterns for the header files."
        )
    endif()

    get_filename_component(_get_files_list_OUTPUT_PATH
      "${CMAKE_CURRENT_BINARY_DIR}/${_TARGET_NAME}"
      ABSOLUTE
    )

    add_custom_command(
        OUTPUT ${_TARGET_NAME}
        COMMAND ${CMAKE_COMMAND}
          -DOUTPUT_PATH="${_get_files_list_OUTPUT_PATH}"
          -DDIRECTORIES="${_get_files_list_DIRECTORIES}"
          -DFILES_PATTERNS="${_get_files_list_FILES_PATTERNS}"
          -P ${_GET_FILES_LIST_SCRIPT}
        COMMENT
          "Searching for files"
    )

    if (DEFINED _get_files_list_COPY_TO)
        # Copy the generated file back to the COPY_TO
        add_custom_target(copy_headers_list_${TARGET_NAME} ALL
            COMMAND
                ${CMAKE_COMMAND} -E copy_if_different ${_TARGET_NAME} ${_get_files_list_COPY_TO}
            DEPENDS "${_TARGET_NAME}"
            COMMENT "Copying ${_TARGET_NAME} to ${_get_files_list_COPY_TO}"
        )
    endif()
endfunction()

function(extract_symbols _TARGET_NAME)

    set(one_value_arguments
      FILTER_PATTERN
      HEADERS_LIST_FILE
      COPY_TO
    )

    set(multi_value_arguments
    )

    cmake_parse_arguments(_extract_symbols
      ""
      "${one_value_arguments}"
      "${multi_value_arguments}"
      ${ARGN}
    )

    # The HEADERS_LIST_FILE argument is required
    if (NOT DEFINED _extract_symbols_HEADERS_LIST_FILE)
        message(FATAL_ERROR "No header files given. Provide a list of header"
                            " files containing exported symbols."
        )
    endif()

    get_filename_component(_extract_symbols_OUTPUT_PATH
      "${CMAKE_CURRENT_BINARY_DIR}/${_TARGET_NAME}"
      ABSOLUTE
    )

    add_custom_target(${_TARGET_NAME}
                      COMMAND ${CMAKE_COMMAND}
                        -DOUTPUT_PATH="${_extract_symbols_OUTPUT_PATH}"
                        -DHEADERS_LIST_FILE="${_extract_symbols_HEADERS_LIST_FILE}"
                        -DFILTER_PATTERN=${_extract_symbols_FILTER_PATTERN}
                        -P ${_EXTRACT_SYMBOLS_SCRIPT}
                      DEPENDS ${_extract_symbols_HEADERS_LIST_FILE}
                      COMMENT "Extracting symbols from headers")

    if (DEFINED _extract_symbols_COPY_TO)
        file(READ "${CMAKE_CURRENT_BINARY_DIR}/${_TARGET_NAME}" SYMBOL_CONTENT)
        string(REPLACE ";" "\n" SYMBOL_CONTENT_NEW "${SYMBOL_CONTENT}")
        file(WRITE "${_extract_symbols_COPY_TO}" "${SYMBOL_CONTENT_NEW}")
    endif()
endfunction()

function(generate_map_file _TARGET_NAME)

    set(options
        FINAL
        BREAK_ABI
    )

    set(one_value_arguments
        RELEASE_NAME_VERSION
        SYMBOLS
        CURRENT_MAP
        COPY_TO
    )

    set(multi_value_arguments
    )

    cmake_parse_arguments(_generate_map_file
      "${options}"
      "${one_value_arguments}"
      "${multi_value_arguments}"
      ${ARGN}
    )

    if (NOT DEFINED _generate_map_file_SYMBOLS)
        message(FATAL_ERROR "No symbols file provided."
        )
    endif()

    if (NOT DEFINED _generate_map_file_RELEASE_NAME_VERSION)
        message(FATAL_ERROR "Release name and version not provided."
          " (e.g. libname_1_0_0"
        )
    endif()

    # Set generated map file path
    get_filename_component(_generate_map_file_OUTPUT_PATH
      "${CMAKE_CURRENT_BINARY_DIR}/${_TARGET_NAME}"
      ABSOLUTE
    )

    add_custom_command(
        OUTPUT ${_TARGET_NAME}
        COMMAND ${CMAKE_COMMAND}
          -DABIMAP_EXECUTABLE=${ABIMAP_EXECUTABLE}
          -DSYMBOLS="${_generate_map_file_SYMBOLS}"
          -DCURRENT_MAP=${_generate_map_file_CURRENT_MAP}
          -DOUTPUT_PATH="${_generate_map_file_OUTPUT_PATH}"
          -DFINAL=${_generate_map_file_FINAL}
          -DBREAK_ABI=${_generate_map_file_BREAK_ABI}
          -DRELEASE_NAME_VERSION=${_generate_map_file_RELEASE_NAME_VERSION}
          -P ${_GENERATE_MAP_SCRIPT}
        DEPENDS ${_generate_map_file_SYMBOLS}
        COMMENT "Generating the map ${_TARGET_NAME}"
    )

    if (DEFINED _generate_map_file_COPY_TO)
        # Copy the generated map back to the COPY_TO
        add_custom_target(copy_map_${_TARGET_NAME} ALL
            COMMAND
                ${CMAKE_COMMAND} -E copy_if_different ${_TARGET_NAME} ${_generate_map_file_COPY_TO}
            DEPENDS "${_TARGET_NAME}"
            COMMENT "Copying ${_TARGET_NAME} to ${_generate_map_file_COPY_TO}"
        )
    endif()
endfunction()
