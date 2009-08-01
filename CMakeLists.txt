project(libssh C)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION "0.3.2")

set(APPLICATION_VERSION_MAJOR "0")
set(APPLICATION_VERSION_MINOR "3")
set(APPLICATION_VERSION_PATCH "2")

set(LIBRARY_VERSION "3.2.0")
set(LIBRARY_SOVERSION "3")

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

find_package(OpenSSL)

if (NOT CRYPTO_FOUND)
  find_package(GCrypt)
  if (NOT GCRYPT_FOUND)
    message(FATAL_ERROR "Could not find OpenSSL or GCrypt")
  endif (NOT GCRYPT_FOUND)
endif (NOT CRYPTO_FOUND)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# check subdirectories
add_subdirectory(doc)
add_subdirectory(include)
add_subdirectory(libssh)

# build samples
include_directories(${CMAKE_SOURCE_DIR}/include)

if (UNIX AND NOT WIN32)
  if (WITH_SFTP AND WITH_SERVER)
    add_executable(samplessh sample.c)
    add_executable(samplesshd samplesshd.c)

    target_link_libraries(samplessh ${LIBSSH_SHARED_LIBRARY})
    target_link_libraries(samplesshd ${LIBSSH_SHARED_LIBRARY})
  endif (WITH_SFTP AND WITH_SERVER)
endif (UNIX AND NOT WIN32)
