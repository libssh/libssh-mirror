project(libssh C)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "0")
set(APPLICATION_VERSION_MINOR "5")
set(APPLICATION_VERSION_PATCH "0")

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

set(LIBRARY_VERSION "4.1.0")
set(LIBRARY_SOVERSION "4")

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

# add definitions
include(DefineCMakeDefaults)
include(DefineCompilerFlags)
include(DefineInstallationPaths)
include(DefineOptions.cmake)
include(CPackConfig.cmake)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# add macros
include(MacroAddPlugin)
include(MacroCopyFile)

# search for libraries
find_package(ZLIB REQUIRED)
find_package(Check)

if (WITH_GCRYPT)
  find_package(GCrypt REQUIRED)
  if (NOT GCRYPT_FOUND)
    message(FATAL_ERROR "Could not find GCrypt")
  endif (NOT GCRYPT_FOUND)
else (WITH_GCRYPT)
  find_package(OpenSSL)
  if (NOT CRYPTO_FOUND)
    find_package(GCrypt)
    if (NOT GCRYPT_FOUND)
      message(FATAL_ERROR "Could not find OpenSSL or GCrypt")
    endif (NOT GCRYPT_FOUND)
  endif (NOT CRYPTO_FOUND)
endif(WITH_GCRYPT)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# check subdirectories
add_subdirectory(doc)
add_subdirectory(include)
add_subdirectory(libssh)

# pkg-config file
configure_file(libssh.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libssh.pc)
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libssh.pc
  DESTINATION
    ${LIB_INSTALL_DIR}/pkgconfig
  COMPONENT
    pkgconfig
)

if (UNIX AND NOT WIN32)
  add_subdirectory(examples)
endif (UNIX AND NOT WIN32)

if (CHECK_FOUND AND WITH_TESTING)
  include(AddCheckTest)
  add_subdirectory(tests)
endif (CHECK_FOUND AND WITH_TESTING)

MESSAGE(STATUS "********************************************")
MESSAGE(STATUS "********** ${PROJECT_NAME} build options : **********")
if (WITH_LIBZ)
MESSAGE(STATUS "zlib support : ON")
else (WITH_LIBZ)
MESSAGE(STATUS "zlib support : OFF")
endif (WITH_LIBZ)

if (WITH_GCRYPT)
MESSAGE(STATUS "libgcrypt support : ON")
else (WITH_GCRYPT)
MESSAGE(STATUS "libgcrypt support : OFF")
endif (WITH_GCRYPT)

if (WITH_SSH1)
MESSAGE(STATUS "SSH-1 support : ON")
else (WITH_SSH1)
MESSAGE(STATUS "SSH-1 support : OFF")
endif (WITH_SSH1)

if (WITH_SFTP)
MESSAGE(STATUS "SFTP support : ON")
else (WITH_SFTP)
MESSAGE(STATUS "SFTP support : OFF")
endif (WITH_SFTP)

if (WITH_SERVER)
MESSAGE(STATUS "Server support : ON")
else (WITH_SERVER)
MESSAGE(STATUS "Server support : OFF")
endif (WITH_SERVER)

if (WITH_PCAP)
MESSAGE(STATUS "Pcap debugging support : ON")
else (WITH_PCAP)
MESSAGE(STATUS "Pcap debugging support : OFF")
endif (WITH_PCAP)

if (WITH_INTERNAL_DOC)
MESSAGE(STATUS "Internal documentation generation")
else (WITH_INTERNAL_DOC)
MESSAGE(STATUS "Public API documentation generation")
endif (WITH_INTERNAL_DOC)

MESSAGE(STATUS "********************************************")



