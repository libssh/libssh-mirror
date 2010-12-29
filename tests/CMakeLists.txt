project(tests C)

set(TORTURE_LIBRARY torture)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${LIBSSH_PRIVATE_INCLUDE_DIRS}
  ${CMOCKERY_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# create test library
add_library(${TORTURE_LIBRARY} STATIC torture.c)
target_link_libraries(${TORTURE_LIBRARY}
    ${CMOCKERY_LIBRARY}
    ${LIBSSH_STATIC_LIBRARY}
    ${LIBSSH_LINK_LIBRARIES}
    ${LIBSSH_THREADS_STATIC_LIBRARY}
    ${LIBSSH_THREADS_LINK_LIBRARIES}
)

set(TEST_TARGET_LIBRARIES ${TORTURE_LIBRARY} ${LIBSSH_LINK_LIBRARIES})

add_subdirectory(unittests)
if (WITH_CLIENT_TESTING)
    add_subdirectory(client)
endif (WITH_CLIENT_TESTING)

if (WITH_BENCHMARKS)
    add_subdirectory(benchmarks)
endif (WITH_BENCHMARKS)

