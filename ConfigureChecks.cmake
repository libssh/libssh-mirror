include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckCXXSourceCompiles)

set(PACKAGE ${APPLICATION_NAME})
set(VERSION ${APPLICATION_VERSION})
set(DATADIR ${DATA_INSTALL_DIR})
set(LIBDIR ${LIB_INSTALL_DIR})
set(PLUGINDIR "${PLUGIN_INSTALL_DIR}-${LIBRARY_SOVERSION}")
set(SYSCONFDIR ${SYSCONF_INSTALL_DIR})

set(BINARYDIR ${CMAKE_BINARY_DIR})
set(SOURCEDIR ${CMAKE_SOURCE_DIR})

# HEADER FILES
check_include_file(pty.h HAVE_PTY_H)
check_include_file(terminos.h HAVE_TERMIOS_H)

check_include_file(openssl/aes.h HAVE_OPENSSL_AES_H)
check_include_file(openssl/blowfish.h HAVE_OPENSSL_BLOWFISH_H)
check_include_file(openssl/des.h HAVE_OPENSSL_DES_H)

# FUNCTIONS
check_function_exists(cfmakeraw HAVE_CFMAKERAW)
if (WIN32)
  set(HAVE_GETADDRINFO TRUE)
  set(HAVE_GETHOSTBYNAME TRUE)
  set(HAVE_SELECT TRUE)
else (WIN32)
  check_function_exists(getaddrinfo HAVE_GETADDRINFO)
  check_function_exists(gethostbyname HAVE_GETHOSTBYNAME)
  check_function_exists(poll HAVE_POLL)
  check_function_exists(select HAVE_SELECT)
endif (WIN32)

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

