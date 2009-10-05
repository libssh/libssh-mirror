# define system dependent compiler flags

include(CheckCCompilerFlag)

if (UNIX AND NOT WIN32)
  if (CMAKE_COMPILER_IS_GNUCC)
    # add -Wconversion ?
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -pedantic -Wall -Wextra -Wshadow -Wmissing-prototypes -Wdeclaration-after-statement -Wunused -Wfloat-equal -Wpointer-arith -Wwrite-strings -Wformat-security -Wmissing-format-attribute")

    # with -fPIC
    check_c_compiler_flag("-fPIC" WITH_FPIC)
    if (WITH_FPIC)
      add_definitions(-fPIC)
    endif (WITH_FPIC)

    check_c_compiler_flag("-fstack-protector" WITH_STACK_PROTECTOR)
    if (WITH_STACK_PROTECTOR)
      add_definitions(-fstack-protector)
    endif (WITH_STACK_PROTECTOR)

    check_c_compiler_flag("-D_FORTIFY_SOURCE=2" WITH_FORTIFY_SOURCE)
    if (WITH_FORTIFY_SOURCE)
      add_definitions(-D_FORTIFY_SOURCE=2)
    endif (WITH_FORTIFY_SOURCE)

  endif (CMAKE_COMPILER_IS_GNUCC)

  if (CMAKE_SIZEOF_VOID_P MATCHES "8")
   # with large file support
   execute_process(
     COMMAND
       getconf LFS64_CFLAGS
     OUTPUT_VARIABLE
       _lfs_CFLAGS
     ERROR_QUIET
     OUTPUT_STRIP_TRAILING_WHITESPACE
   )
 else (CMAKE_SIZEOF_VOID_P MATCHES "8")
   # with large file support
   execute_process(
     COMMAND
       getconf LFS_CFLAGS
     OUTPUT_VARIABLE
       _lfs_CFLAGS
     ERROR_QUIET
     OUTPUT_STRIP_TRAILING_WHITESPACE
   )
 endif (CMAKE_SIZEOF_VOID_P MATCHES "8")
 if (_lfs_CFLAGS)
   string(REGEX REPLACE "[\r\n]" " " "${_lfs_CFLAGS}" "${${_lfs_CFLAGS}}")
   add_definitions(${_lfs_CFLAGS})
 endif (_lfs_CFLAGS)

endif (UNIX AND NOT WIN32)

# suppress warning about "deprecated" functions
if (MSVC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif (MSVC)
