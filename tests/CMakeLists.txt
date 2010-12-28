project(tests C)

if (UNIX AND NOT LINUX)
    find_package(Argp)
endif (UNIX AND NOT LINUX)

set(TORTURE_LIBRARY torture)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${CHECK_INCLUDE_DIRS}
  ${ARGP_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# create test library
add_library(${TORTURE_LIBRARY} SHARED torture.c cmdline.c)
target_link_libraries(${TORTURE_LIBRARY}
    ${CHECK_LIBRARIES}
    ${LIBSSH_STATIC_LIBRARY}
    ${LIBSSH_LINK_LIBRARIES}
    ${LIBSSH_THREADS_STATIC_LIBRARY}
    ${LIBSSH_THREADS_LINK_LIBRARIES}
    ${ARGP_LIBRARIES}
)

set(TEST_TARGET_LIBRARIES ${SUPPORT_LIBRARY} ${LIBSSH_LINK_LIBRARIES})

add_subdirectory(unittests)
if (WITH_CLIENT_TESTING)
    add_subdirectory(client)
endif (WITH_CLIENT_TESTING)

if (WITH_BENCHMARKS)
    add_subdirectory(benchmarks)
endif (WITH_BENCHMARKS)	

