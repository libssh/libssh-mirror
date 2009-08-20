include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckCXXSourceCompiles)
include(TestBigEndian)

set(PACKAGE ${APPLICATION_NAME})
set(VERSION ${APPLICATION_VERSION})
set(DATADIR ${DATA_INSTALL_DIR})
set(LIBDIR ${LIB_INSTALL_DIR})
set(PLUGINDIR "${PLUGIN_INSTALL_DIR}-${LIBRARY_SOVERSION}")
set(SYSCONFDIR ${SYSCONF_INSTALL_DIR})

set(BINARYDIR ${CMAKE_BINARY_DIR})
set(SOURCEDIR ${CMAKE_SOURCE_DIR})

if(CMAKE_COMPILER_IS_GNUC)
check_c_compiler_flag("-fvisibility=hidden" WITH_VISIBILITY_HIDDEN)
endif(CMAKE_COMPILER_IS_GNUC)

# HEADER FILES
check_include_file(pty.h HAVE_PTY_H)
check_include_file(terminos.h HAVE_TERMIOS_H)
if (WIN32)
  check_include_file(wspiapi.h HAVE_WSPIAPI_H)
  set(HAVE_GETADDRINFO TRUE)
  set(HAVE_GETHOSTBYNAME TRUE)
  set(HAVE_SELECT TRUE)
endif (WIN32)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/aes.h HAVE_OPENSSL_AES_H)
set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/blowfish.h HAVE_OPENSSL_BLOWFISH_H)
set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/des.h HAVE_OPENSSL_DES_H)

# FUNCTIONS
check_function_exists(cfmakeraw HAVE_CFMAKERAW)
if (UNIX)
  check_function_exists(getaddrinfo HAVE_GETADDRINFO)
  if (NOT HAVE_GETADDRINFO)
    check_library_exists("socket" "getaddrinfo" "" HAVE_LIB_GETADDRINFO)
    set(HAVE_GETADDRINFO 1)
  endif (NOT HAVE_GETADDRINFO)
  check_function_exists(gethostbyname HAVE_GETHOSTBYNAME)
  if (NOT HAVE_GETHOSTBYNAME)
    check_library_exists("nsl" "gethostbyname" "" HAVE_LIB_GETHOSTBYNAME)
    set(HAVE_GETHOSTBYNAME 1)
  endif (NOT HAVE_GETHOSTBYNAME)
  check_function_exists(poll HAVE_POLL)
  check_function_exists(select HAVE_SELECT)
  check_function_exists(regcomp HAVE_REGCOMP)
endif (UNIX)

# LIBRARIES
if (CRYPTO_FOUND)
  set(HAVE_LIBCRYPTO 1)
endif (CRYPTO_FOUND)

if (GCRYPT_FOUND)
  set(HAVE_LIBGCRYPT 1)
endif (GCRYPT_FOUND)

if (Z_LIBRARY)
  set(HAVE_LIBZ 1)
endif (Z_LIBRARY)

# OPTIONS
if (WITH_DEBUG_CRYPTO)
  set(DEBUG_CRYPTO 1)
endif (WITH_DEBUG_CRYPTO)

if (WITH_DEBUG_CALLTRACE)
  set(DEBUG_CALLTRACE 1)
endif (WITH_DEBUG_CALLTRACE)

# ENDIAN
test_big_endian(WORDS_BIGENDIAN)
