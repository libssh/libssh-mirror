project(libssh C)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "0")
set(APPLICATION_VERSION_MINOR "5")
set(APPLICATION_VERSION_PATCH "4")

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

# SOVERSION scheme: CURRENT.AGE.REVISION
#   If there was an incompatible interface change:
#     Increment CURRENT. Set AGE and REVISION to 0
#   If there was a compatible interface change:
#     Increment AGE. Set REVISION to 0
#   If the source code was changed, but there were no interface changes:
#     Increment REVISION.
set(LIBRARY_VERSION "4.2.4")
set(LIBRARY_SOVERSION "4")

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

# add definitions
include(DefineCMakeDefaults)
include(DefinePlatformDefaults)
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
if (WITH_LIBZ)
    find_package(ZLIB REQUIRED)
endif (WITH_LIBZ)

if (WITH_GCRYPT)
  find_package(GCrypt REQUIRED)
  if (NOT GCRYPT_FOUND)
    message(FATAL_ERROR "Could not find GCrypt")
  endif (NOT GCRYPT_FOUND)
else (WITH_GCRYPT)
  find_package(OpenSSL)
  if (NOT OPENSSL_FOUND)
    find_package(GCrypt)
    if (NOT GCRYPT_FOUND)
      message(FATAL_ERROR "Could not find OpenSSL or GCrypt")
    endif (NOT GCRYPT_FOUND)
  endif (NOT OPENSSL_FOUND)
endif(WITH_GCRYPT)

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# check subdirectories
add_subdirectory(doc)
add_subdirectory(include)
add_subdirectory(src)

# pkg-config file
configure_file(libssh.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libssh.pc)
configure_file(libssh_threads.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libssh_threads.pc)
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libssh.pc
    ${CMAKE_CURRENT_BINARY_DIR}/libssh_threads.pc
  DESTINATION
    ${LIB_INSTALL_DIR}/pkgconfig
  COMPONENT
    pkgconfig
)

add_subdirectory(examples)

if (WITH_TESTING)
  find_package(CMockery REQUIRED)
  include(AddCMockeryTest)
  add_subdirectory(tests)
endif (WITH_TESTING)


message(STATUS "********************************************")
message(STATUS "********** ${PROJECT_NAME} build options : **********")

message(STATUS "zlib support: ${WITH_LIBZ}")
message(STATUS "libgcrypt support: ${WITH_GCRYPT}")
message(STATUS "SSH-1 support: ${WITH_SSH1}")
message(STATUS "SFTP support: ${WITH_SFTP}")
message(STATUS "Server support : ${WITH_SERVER}")
message(STATUS "Pcap debugging support : ${WITH_PCAP}")
message(STATUS "Unit testing: ${WITH_TESTING}")
message(STATUS "Client code Unit testing: ${WITH_CLIENT_TESTING}")
if (WITH_INTERNAL_DOC)
    message(STATUS "Internal documentation generation")
else (WITH_INTERNAL_DOC)
    message(STATUS "Public API documentation generation")
endif (WITH_INTERNAL_DOC)
message(STATUS "Benchmarks: ${WITH_BENCHMARKS}")
message(STATUS "********************************************")

